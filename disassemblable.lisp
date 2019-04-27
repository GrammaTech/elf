;;; disassemblable --- Extensions for disassemblable ELF files
(in-package :elf)

;;; Disassembly classes and functions
(defclass disassemblable (elf) ())

#+sbcl
(defclass capstone (disassemblable) ())

(defclass objdump (disassemblable) ())

(defclass csurf (disassemblable)
  ((sw-project :initarg :project :accessor project :initform nil)))

(defclass elf-const (disassemblable)
  ((disassembly :initarg :disassembly :accessor disassembly
                :initform (make-hash-table :test 'equal)))
  (:documentation
   "Disassemblable objects with caches holding disassembly by section name."))

(defclass tsl (disassemblable) ())

(defclass objdump-const (elf-const objdump) ()
  (:documentation "Caching objdump-backed ELF file."))

(defgeneric disassemble-section (disassemblable section)
  (:documentation
   "Return the disassembly of the contents of SECTION in DISASSEMBLABLE.
The contents are returned grouped by function."))

(defmethod disassemble-section :around ((elf elf-const) section-name)
  (with-slots (disassembly) elf
    (or (gethash section-name disassembly)
        (setf (gethash section-name disassembly) (call-next-method)))))


;;; Disassembly functions using objdump from GNU binutils
(defvar objdump-cmd "objdump" "Name of the objdump executable.")

(defun objdump (section)
  (with-temp-file path
    (write-elf (elf section) path)
    (shell (format nil "~a -j ~a -d ~a" objdump-cmd (name section) path))))

(defvar *single-value-objdump-hack* nil
  "Set to non-nil if objdump prints 4-byte values as a single number.")

(defun parse-objdump-line (lines)
  "Parse line of objdump output into (address raw instruction)."
  (mapcar
   (lambda (line)
     (destructuring-bind (address-str bytes-str . disasm-str)
         (split-sequence #\Tab line)
       (list
        (parse-integer (trim address-str) :radix 16 :junk-allowed t)
        ;; bytes
        (let ((raw-bytes (mapcar (lambda (num) (parse-integer num :radix 16))
                                 (split-sequence #\Space (trim bytes-str)))))
          ;; If only 1 byte is returned,
          (if (or (not *single-value-objdump-hack*)
                  (> (length raw-bytes) 1))
              raw-bytes
              ;; then split it into four bytes.
              (mappend (lambda (raw) (coerce (int-to-bytes raw 4) 'list))
                       raw-bytes)))
        ;; disassembled assembly text
        (from-string (make-instance 'objdump-instruction)
                     (format nil "~{~a~^ ~}" disasm-str)))))
   (remove-if (lambda (line)
                (or (< (length line) 9)
                    (not (scan-to-strings "[0-9a-f]+:" line))))
              lines)))

(defun objdump-parse (output)
  "Parse the output of `objdump' returning the disassembly by symbol."
  (let ((lines (split-sequence #\Newline output))
        (sec-header (lambda (line)
                      (multiple-value-bind (matchedp matches)
                          (scan-to-strings "^([0-9a-f]+) <(.+)>:$" line)
                        (when matchedp
                          (cons
                           (parse-integer (aref matches 0) :radix 16)
                           (aref matches 1)))))))
    (mapcar #'cons
            (remove nil (mapcar sec-header lines))
            (mapcar #'parse-objdump-line
                    (cdr (split-sequence-if sec-header lines))))))

(defmethod disassemble-section ((elf objdump) section-name)
  (objdump-parse (objdump (named-section elf section-name))))


;;; Disassembly functions using csurf from GrammaTech
(defvar csurf-cmd "csurf -nogui")

(defvar csurf-script
  (make-pathname
   :directory
   (pathname-directory #.(or *compile-file-truename*
                             *load-truename*
                             *default-pathname-defaults*))
   :name "sections"
   :type "stk"))

(defmethod csurf-ins (sw-project section)
  (multiple-value-bind (stdout stderr errno)
      (shell (format nil "~a ~a -l ~a -- ~a"
                     csurf-cmd sw-project csurf-script section))
    (unless (zerop errno)
      (error "csurf failed with ~s" stderr))
    ;; parse addresses
    (mapcar (lambda (line)
              (multiple-value-bind (matchp matches)
                  (scan-to-strings "^([0-9]+)[\\s]+(.*)$" line)
                (declare (ignorable matchp))
                (cons (parse-integer (aref matches 0))
                      (aref matches 1))))
            (split-sequence #\Newline stdout :remove-empty-subseqs t))))

(defmethod disassemble-section ((elf csurf) section-name &aux last)
  ;; Implementation of disasm using the objdump support provided by
  ;; the ELF library.
  (let ((data (data (named-section elf section-name)))
        (offset (address (sh (named-section elf section-name)))))
    (cdr (mapcar (lambda (pair)
                   (prog1 (when last
                            (list (+ (car last) offset)
                                  (coerce (subseq data (car last) (car pair))
                                          'list)
                                  (cdr last)))
                     (setf last pair)))
                 (append (csurf-ins (sw-project elf) section-name)
                         (list (cons (length data) "NO disasm")))))))


;;; Disassembly functions using TSL-decoders from GrammaTech
(defvar decoding-cmds '((:386 "ia32show")
                        (:arm "armshow"))
  "Name of the decoding commands listed by `machine'.
Where `machine' is the elf header field.")

(defun decode (section)
  "Return the string representation of the instructions in SECTION."
  (let ((cmd (second (assoc (machine (header (elf section))) decoding-cmds))))
    (with-open-stream (in (make-in-memory-input-stream (data section)))
      #+sbcl (sb-ext:process-output
              (sb-ext:run-program
               cmd nil :input in :output :stream :search t :wait nil))
      #-sbcl (error "This lisp does not support `shell-stream'."))))

(defmethod disassemble-section ((elf tsl) section-name)
  (with-open-stream (instrs (decode (named-section elf section-name)))
    (loop :for line = (read-line instrs nil :eof t) :until (eq line :eof)
       :collect (from-string (make-instance 'tsl-instruction) line))))


;;; Disassembly functions using SB-CAPSTONE (assuming X86-64)

#+sbcl
(defun copy-c-string (src dest &aux (index 0))
  (loop (let ((b (sb-sys:sap-ref-8 src index)))
          (when (= b 0)
            (setf (fill-pointer dest) index)
            (return))
          (setf (char dest index) (code-char b))
          (incf index))))

#+sbcl
(defun c-bytes (sap size)
  (let ((s (make-array size :element-type '(unsigned-byte 8))))
    (dotimes (i size)
      (setf (aref s i)
            (sb-sys:sap-ref-8 sap i)))
    s))

#+sbcl
(defun parse-capstone-operand (string &aux p)
  (cond ((starts-with-subseq "0x" string)
         (parse-integer string :radix 16 :start 2))
        ((starts-with-subseq "[" string)
         (list :deref (parse-capstone-operand (subseq string 1 (1- (length string))))))
        ((starts-with-subseq "byte ptr " string)
         (list :byte (parse-capstone-operand (subseq string 9))))
        ((starts-with-subseq "word ptr " string)
         (list :word (parse-capstone-operand (subseq string 9))))
        ((starts-with-subseq "dword ptr " string)
         (list :dword (parse-capstone-operand (subseq string 10))))
        ((starts-with-subseq "qword ptr " string)
         (list :qword (parse-capstone-operand (subseq string 10))))
        ((starts-with-subseq "tbyte ptr " string)
         (list :tbyte (parse-capstone-operand (subseq string 10))))
        ((starts-with-subseq "cs:" string)
         (list (list :seg :cs) (parse-capstone-operand (subseq string 3))))
        ((starts-with-subseq "ds:" string)
         (list (list :seg :ds) (parse-capstone-operand (subseq string 3))))
        ((starts-with-subseq "es:" string)
         (list (list :seg :es) (parse-capstone-operand (subseq string 3))))
        ((starts-with-subseq "fs:" string)
         (list (list :seg :fs) (parse-capstone-operand (subseq string 3))))
        ((starts-with-subseq "gs:" string)
         (list (list :seg :gs) (parse-capstone-operand (subseq string 3))))
        ((setq p (search " + " string))
         (list :+
               (parse-capstone-operand (subseq string 0 p))
               (parse-capstone-operand (subseq string (+ p 3)))))
        ((setq p (search " - " string))
         (list :-
               (parse-capstone-operand (subseq string 0 p))
               (parse-capstone-operand (subseq string (+ p 3)))))
        ((setq p (search "*" string))
         (list :*
               (parse-capstone-operand (subseq string 0 p))
               (parse-capstone-operand (subseq string (1+ p)))))
        ((every #'digit-char-p string)
         (parse-integer string))
        (t
         (make-keyword (string-upcase string)))))

#+sbcl
(defun parse-capstone-operands (operands)
  (if (equal operands "")
      nil
      (mapcar (lambda (s) (parse-capstone-operand (string-trim " " s)))
              (split-sequence:split-sequence #\, operands))))

#+sbcl
(defun capstone-disassemble-bytes (bytes size)
  (let ((instructions '()))
    (sb-sys:with-pinned-objects (bytes)
      (let* ((base (sb-sys:vector-sap bytes))
             (target '(:x86-64 :little-endian))
             (insn-addr (sb-sys:sap-int base))
             (starting-vaddr 0))
        (multiple-value-bind (return-code handle)
            (sb-capstone:cs-open-for-target target)
          (declare (ignore return-code))
          (sb-capstone:cs-option handle sb-capstone:cs-opt-detail sb-capstone:cs-opt-on)
          (let ((insn (sb-capstone:cs-malloc handle))
                (mnemonic (make-array 31 :element-type 'base-char :fill-pointer t))
                (operands (make-array 159 :element-type 'base-char :fill-pointer t)))
            (sb-alien:with-alien ((paddr sb-alien:unsigned)
                                  (vaddr sb-alien:unsigned)
                                  (remaining sb-alien:unsigned))
              (setq paddr insn-addr
                    vaddr starting-vaddr
                    remaining size)
              (loop
               (multiple-value-bind (successful new-paddr new-remaining new-vaddr)
                   (sb-capstone:cs-disasm-iter handle paddr remaining vaddr insn)
                 (setf paddr new-paddr
                       remaining new-remaining
                       vaddr new-vaddr)
                 (unless successful
                   (return))
                 (copy-c-string
                  (sb-alien:alien-sap (sb-alien:slot insn 'sb-capstone:insn-mnemonic))
                  mnemonic)
                 (copy-c-string
                  (sb-alien:alien-sap (sb-alien:slot insn 'sb-capstone:insn-operands))
                  operands)
                 (push
                  (list
                   (c-bytes
                    (sb-alien:alien-sap (sb-alien:slot insn 'sb-capstone:insn-bytes))
                    (sb-alien:slot insn 'sb-capstone:insn-size))
                   (list*
                    (make-keyword (string-upcase mnemonic))
                    (parse-capstone-operands operands)))
                  instructions))))
            (sb-capstone:cs-free insn 1)
            (sb-capstone:cs-close handle)))))
    (nreverse instructions)))

#+sbcl
(defmethod disassemble-section ((elf capstone) section-name)
  (let ((section (named-section elf section-name)))
    (capstone-disassemble-bytes (data section)
                                (length (data section)))))
