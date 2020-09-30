;; Copyright (C) 2011-2013 Eric Schulte
(defsystem "elf"
  :name "elf"
  :author "Eric Schulte <schulte.eric@gmail.com>"
  :description "Common Lisp library for manipulation of ELF files."
  :version "0.1"
  :depends-on (alexandria
               com.gigamonkeys.binary-data
               metabang-bind
               split-sequence
               #-ecl trivial-shell
               cl-ppcre
               flexi-streams
               #+sbcl sb-capstone)
  :components ((:file "package")
               (:file "util" :depends-on ("package"))
               (:file "elf" :depends-on ("package" "util"))
               (:file "arm" :depends-on ("package" "util" "elf"))
               (:file "instruction" :depends-on ("package"))
               (:file #.(if (handler-case (progn (require :sb-capstone) t)
                              (error () nil))
                            "disassemblable"
                            "disassemblable-light")
                      :depends-on ("package" "util" "elf" "instruction")))
  :in-order-to ((test-op (load-op "elf/test")))
  :perform (test-op (o c) (symbol-call :elf/test '#:test)))

(defsystem "elf/test"
  :description "Test the elf library."
  :version "0.0.0"
  :depends-on
  (alexandria metabang-bind elf stefil trivial-timeout)
  :components
  ((:static-file "COPYING")
   (:module "test"
            :components
            ((:file "package")
             (:file "elf-test" :depends-on ("package"))))))
