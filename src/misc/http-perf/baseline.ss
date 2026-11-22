;; -*- Gerbil -*-
(import :std/cli/getopt
        :std/error
        :std/io
        :std/net/address
        (only-in :std/os/socket SHUT_WR))
(export main)

(def content
  "Hello!")

(def response
  (string->utf8
   (string-append
    "HTTP/1.1 200 OK\r\n"
    "Connection: close\r\n"
    "Content-Length: " (number->string (string-length content)) "\r\n"
    "Content-Type: text/plain\r\n"
    "\r\n"
    content)))

;; send may write fewer bytes than requested; send the rest until all of data is written.
(def (send-all cli (data : :u8vector))
  (let loop ((start 0))
    (when (fx< start (u8vector-length data))
      (loop (fx+ start (StreamSocket-send cli data start))))))

(def (handle-client cli)
  (try
   (let (buf (make-u8vector 65536))
     (StreamSocket-recv cli buf)
     (send-all cli response)
     (StreamSocket-shutdown cli SHUT_WR))
   (finally
    (ignore-errors (StreamSocket-close cli)))))

(def (run-server address)
  (let ((sock (tcp-listen (string->address address))))
    (let lp ()
      (let (cli (ServerSocket-accept sock))
        (spawn handle-client cli)
        (lp)))))

(def (main . args)
  (def gopt
    (getopt (option 'address "-a" "--address"
                    help: "server address"
                    default: "inet4:127.0.0.1:8080")
            (optional-argument 'count help: "number of requests to serve"
                               default: #f
                               value: string->number)))

  (try
   (let (opt (getopt-parse gopt args))
     (run-server (hash-get opt 'address)))
   (catch (getopt-error? exn)
     (getopt-display-help exn "baseline" (current-error-port))
     (exit 1))))
