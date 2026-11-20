;;; -*- Gerbil -*-
;;; © gerbil contributors
;;; S3 integration tests — in-memory HTTP service with synthetic credentials.

(import :std/crypto/digest
        :std/encoding/hex
        :std/error
        :std/io
        :std/log
        :std/net/address
        :std/net/http/server
        (prefix-in :std/net/http/client http.)
        :std/net/url
        :std/test
        (only-in :std/test/base raise-test-error)
        :std/text/pregexp
        :std/time/timeout
        ../s3)
(export client-test test-setup! test-cleanup!)

(def fixture-mutex (make-mutex 'client-test))
(def buckets (make-hash-table))
(def observed [])
(def server #f)
(def server-host "127.0.0.1:20004")
(def server-endpoint (string-append "http://" server-host))

(def (test-setup!) => :void
  (do-with-lock fixture-mutex
    (set! buckets (make-hash-table))
    (set! observed []))
  (set! server
    (new-http-server
     (ServerConfig
      mux: (new-static-mux rest: "" (new-closure-handler s3-handler))
      log: (stderr-log-sink)
      listen: [(string-append "inet4:" server-host)])))
  (using (server server : Server)
    (server.start!)))

(def (test-cleanup!) => :void
  (when server
    (using (server server : Server)
      (server.stop!))
    (set! server #f)))

(def (test-client)
  (s3-client endpoint: server-endpoint path-style: #t
            access-key: "test-access-key" secret-key: "test-secret-key"
            region: "us-east-1"))

(def (header-value headers name)
  (cond
   ((assoc name headers) => cdr)
   (else #f)))

(def (last-request)
  (do-with-lock fixture-mutex (car observed)))

;; Route and mutate state under the mutex, but never hold it during network I/O.
;; Stored objects are pairs of bytes and content type; observations are vectors
;; of method, path, headers, and bytes.
(def (s3-handler (req :- Request) (res :- ResponseHandler))
  (def method req.method)
  (def path (URL-path req.url))
  (def headers req.headers)
  (def body (read-all-from-reader req.body))
  (def (xml status text)
    (list status "application/xml" (string->utf8 text)))
  (def (empty status)
    (list status "application/octet-stream" '#u8()))
  (def (failure status code)
    (xml status (string-append "<Error><Code>" code "</Code></Error>")))
  (def reply
    (do-with-lock fixture-mutex
      (set! observed (cons (vector method path headers body) observed))
      (if (equal? path "/")
        (if (equal? method "GET")
          (xml OK
               (string-append
                "<ListAllMyBucketsResult xmlns=\"http://doc.s3.amazonaws.com/2006-03-01\"><Buckets>"
                (apply string-append
                       (map (lambda (name)
                              (string-append "<Bucket><Name>" name "</Name></Bucket>"))
                            (list-sort string<? (hash-keys buckets))))
                "</Buckets></ListAllMyBucketsResult>"))
          (empty Method-Not-Allowed))
        (let* ((parts (string-split (substring path 1 (string-length path)) #\/))
               (name (car parts))
               (key (string-join (cdr parts) "/"))
               (objects (hash-get buckets name)))
          (cond
           ((equal? name "forbidden")
            (failure Forbidden "AccessDenied"))
           ((string-empty? key)
            (cond
             ((equal? method "PUT")
              (if objects
                (failure Conflict "BucketAlreadyOwnedByYou")
                (begin (hash-put! buckets name (make-hash-table)) (empty OK))))
             ((not objects) (failure Not-Found "NoSuchBucket"))
             ((equal? method "HEAD") (empty OK))
             ((equal? method "DELETE")
              (if (null? (hash-keys objects))
                (begin (hash-remove! buckets name) (empty No-Content))
                (failure Conflict "BucketNotEmpty")))
             ((equal? method "GET")
              (xml OK
                   (string-append
                    "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                    (apply string-append
                           (map (lambda (key)
                                  (string-append "<Contents><Key>" key "</Key></Contents>"))
                                (list-sort string<? (hash-keys objects))))
                    "</ListBucketResult>")))
             (else (empty Method-Not-Allowed))))
           ((not objects) (failure Not-Found "NoSuchBucket"))
           ((equal? method "PUT")
            (let (source (header-value headers "X-Amz-Copy-Source"))
              (if source
                (let* ((parts (string-split source #\/))
                       (source-bucket (hash-get buckets (car parts)))
                       (object (and source-bucket
                                    (hash-get source-bucket (string-join (cdr parts) "/")))))
                  (if object
                    (begin
                      (hash-put! objects key object)
                      (xml OK "<CopyObjectResult><ETag>synthetic</ETag></CopyObjectResult>"))
                    ;; S3 can return an embedded copy error with HTTP 200.
                    (failure OK "NoSuchKey")))
                (begin
                  (hash-put! objects key
                             (cons body (header-value headers "Content-Type")))
                  (empty OK)))))
           ((equal? method "DELETE")
            (hash-remove! objects key)
            (empty No-Content))
           (else
            (let (object (hash-get objects key))
              (cond
               ((not object) (failure Not-Found "NoSuchKey"))
               ((equal? method "HEAD") (empty OK))
               ((equal? method "GET") (list OK (cdr object) (car object)))
               (else (empty Method-Not-Allowed))))))))))
  (match reply
    ([status content-type data]
     (res.write! status [(cons "Content-Type" content-type)] data))))

;; Unlike http/server, this fixture does not close after writing the response.
;; Each request must produce client EOF before any server-side cleanup runs.
(def (with-s3-response response action)
  (let ((listener (tcp-listen (InetAddress localhost4 0)))
        (lock (make-mutex 's3-response))
        (peer #f)
        (stopping? #f)
        (worker #f))
    (try
     (ServerSocket-set-input-timeout! listener (IOTimeout 3))
     (set! worker
       (spawn
        (lambda ()
          (with-catch
           (lambda (e) [e])
           (lambda ()
             (for-each
              (lambda (reply)
                (let (sock (ServerSocket-accept listener))
                  (try
                   (do-with-lock lock
                     (when stopping?
                       (raise-io-closed with-s3-response "Fixture stopped"))
                     (set! peer sock))
                   (StreamSocket-set-input-timeout! sock (IOTimeout 3))
                   (StreamSocket-set-output-timeout! sock (IOTimeout 3))
                   (using ((reader (open-buffered-reader (StreamSocket-reader sock)) : BufferedReader)
                           (writer (open-buffered-writer (StreamSocket-writer sock)) : BufferedWriter))
                     (let loop ()
                       (let (line (reader.read-line-utf8 '(#\return #\newline)))
                         (when (eof-object? line)
                           (raise-test-error with-s3-response "EOF before request headers"))
                         (unless (string-empty? line) (loop))))
                     (writer.write-string-utf8 reply)
                     (writer.flush)
                     (unless (eof-object? (reader.read-u8))
                       (raise-test-error with-s3-response "Expected client EOF after response")))
                   (finally (ignore-errors (StreamSocket-close sock))))))
              ["HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" response])
             #t)))))
     ;; Bound client reads as well, so a broken fixture cannot hang the suite.
     (parameterize ((http.http-connect
                     (lambda (address)
                       (let (sock (tcp-connect address (IOTimeout 3)))
                         (StreamSocket-set-input-timeout! sock (IOTimeout 3))
                         (StreamSocket-set-output-timeout! sock (IOTimeout 3))
                         sock))))
       (using (client
               (s3-client
                endpoint: (string-append "http://127.0.0.1:"
                                         (number->string
                                          (InetAddress-port (ServerSocket-address listener))))
                path-style: #t access-key: "x" secret-key: "y")
               : S3Client)
         (let (bucket (client.create-bucket! "test"))
           (action client bucket))))
     (let (result (thread-join! worker 5 'timeout))
       (cond
        ((eq? result 'timeout)
         (raise-test-error with-s3-response "Timed out waiting for client EOF"))
        ((pair? result) (raise (car result)))
        ((not (eq? result #t))
         (raise-test-error with-s3-response "Unexpected worker result" result))))
     (finally
       (ignore-errors (ServerSocket-close listener))
       (do-with-lock lock
         (set! stopping? #t)
         (when peer (ignore-errors (StreamSocket-close peer))))
       (when worker
         (ignore-errors (thread-terminate! worker))
         (ignore-errors (thread-join! worker 5)))))))

(def (s3-test-response body (status "200 OK"))
  (string-append "HTTP/1.1 " status "\r\nContent-Length: "
                 (number->string (u8vector-length (string->utf8 body)))
                 "\r\n\r\n" body))

(def client-test
  (test-suite "test :std/net/s3 client"
    (test-case "response consumers close on successful reads"
      (with-s3-response
       (s3-test-response "<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>")
       (lambda ((client : S3Client) bucket)
         (check (client.list-buckets) => [])))
      (with-s3-response
       (s3-test-response "<ListBucketResult/>")
       (lambda (client (bucket : S3Bucket))
         (check (bucket.list-objects) => [])))
      (with-s3-response
       (s3-test-response "payload")
       (lambda (client (bucket : S3Bucket))
         (check (bucket.get "key") => (string->utf8 "payload"))))
      (with-s3-response
       (s3-test-response "<CopyObjectResult/>")
       (lambda (client (bucket : S3Bucket))
         (check (bucket.copy-to! "test/source" "dest") => (void)))))

    (test-case "XML and copy errors still close responses"
      (with-s3-response
       (s3-test-response
        "<ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Buckets><Bucket/></Buckets></ListAllMyBucketsResult>")
       (lambda ((client : S3Client) bucket)
         (check-exception (client.list-buckets) contract-violation-error?)))
      (for-each
       (lambda (action)
         (with-s3-response
          (s3-test-response "<broken>")
          (lambda (client bucket)
            (check-exception (action client bucket) Exception?))))
       [(lambda ((client : S3Client) bucket) (client.list-buckets))
        (lambda (client (bucket : S3Bucket)) (bucket.list-objects))
        (lambda (client (bucket : S3Bucket)) (bucket.copy-to! "test/source" "dest"))])
      (for-each
       (lambda (status)
         (with-s3-response
          (s3-test-response "<Error><Code>NoSuchKey</Code></Error>" status)
          (lambda (client (bucket : S3Bucket))
            (check-exception (bucket.copy-to! "test/missing" "dest") s3-client-error?))))
       ["200 OK" "404 Not Found"]))

    (test-case "body read errors close responses before server cleanup"
      (for-each
       (lambda (action)
         (with-s3-response
          "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nnot-hex\r\n"
          (lambda (client bucket)
            (check-exception (action client bucket) io-error?))))
       [(lambda ((client : S3Client) bucket) (client.list-buckets))
        (lambda (client (bucket : S3Bucket)) (bucket.list-objects))
        (lambda (client (bucket : S3Bucket)) (bucket.get "key"))
        (lambda (client (bucket : S3Bucket)) (bucket.copy-to! "test/source" "dest"))]))

    (test-case "responses in both S3 namespaces, non-ASCII keys and error codes"
      (for-each
       (lambda (uri)
         (with-s3-response
          (s3-test-response
           (string-append "<ListAllMyBucketsResult xmlns='" uri "'><Buckets>"
                          "<Bucket><Name>one</Name></Bucket><Bucket><Name>two</Name></Bucket>"
                          "</Buckets></ListAllMyBucketsResult>"))
          (lambda ((client : S3Client) bucket)
            (check (length (client.list-buckets)) => 2)))
         (with-s3-response
          (s3-test-response
           (string-append "<?xml version='1.0' encoding='UTF-8'?>"
                          "<ListBucketResult xmlns='" uri "'>"
                          "<Contents><Key>λ/日本語/😀</Key></Contents>"
                          "<Contents><Key>a &amp; b</Key></Contents></ListBucketResult>"))
          (lambda (client (bucket : S3Bucket))
            (check (bucket.list-objects) => ["λ/日本語/😀" "a & b"])))
         (with-s3-response
          (s3-test-response
           (string-append "<Error xmlns='" uri "'><Code>AccessDenied</Code></Error>"))
          (lambda (client (bucket : S3Bucket))
            (check-exception (bucket.copy-to! "test/source" "dest")
                             (lambda (e)
                               (and (s3-client-error? e)
                                    (equal? (cadr (error-irritants e)) "AccessDenied")))))))
       ["http://s3.amazonaws.com/doc/2006-03-01/"
        "http://doc.s3.amazonaws.com/2006-03-01"])
      (with-s3-response
       (s3-test-response "<Error><Message>no code</Message></Error>")
       (lambda (client (bucket : S3Bucket))
         (check-exception (bucket.copy-to! "test/source" "dest")
                          (lambda (e)
                            (and (s3-client-error? e)
                                 (equal? (cadr (error-irritants e)) "Unknown")))))))

    (test-case "default and hostname endpoints construct without requests"
      (check (S3Client? (s3-client access-key: "x" secret-key: "y")) => #t)
      (check (S3Client? (s3-client endpoint: "s3.amazonaws.com"
                                  access-key: "x" secret-key: "y"))
             => #t))

    (test-case "credentials are required"
      (check-exception
       (s3-client access-key: #f secret-key: "test-secret-key")
       s3-client-error?)
      (check-exception
       (s3-client access-key: "test-access-key" secret-key: #f)
       s3-client-error?))

    (test-case "bucket lifecycle and both listing namespaces"
      (using (client (test-client) : S3Client)
        (check (client.list-buckets) => [])
        (check (client.bucket-exists? "lifecycle") => #f)
        (check-exception (client.get-bucket "lifecycle") s3-client-error?)
        (using (bucket (client.create-bucket! "lifecycle") : S3Bucket)
          (check (bucket.list-objects) => []))
        (check-exception (client.create-bucket! "lifecycle") s3-client-error?)
        (check (client.bucket-exists? "lifecycle") => #t)
        (using (bucket (client.get-bucket "lifecycle") : S3Bucket)
          (check (bucket.list-objects) => []))
        (let (listed (client.list-buckets))
          (check (length listed) => 1)
          (using (bucket (car listed) : S3Bucket)
            (check (bucket.list-objects) => [])))
        (client.delete-bucket! "lifecycle")
        (client.delete-bucket! "lifecycle")
        (check (client.bucket-exists? "lifecycle") => #f)
        (check (client.list-buckets) => [])))

    (test-case "binary objects, copy, and signing envelope"
      (using ((client (test-client) : S3Client)
              (bucket (client.create-bucket! "objects") : S3Bucket))
        (def data '#u8(0 1 127 128 254 255 13 10))
        (check (bucket.exists? "nested/data.bin") => #f)
        (bucket.put! "nested/data.bin" data content-type: "application/x-s3-test")
        (let* ((request (last-request))
               (headers (vector-ref request 2))
               (timestamp (header-value headers "X-Amz-Date"))
               (authorization (header-value headers "Authorization")))
          (check (vector-ref request 0) => "PUT")
          (check (vector-ref request 1) => "/objects/nested/data.bin")
          (check (vector-ref request 3) => data)
          (check (header-value headers "Host") => server-host)
          (check (length (filter (lambda (h) (string-ci=? (car h) "Host")) headers)) => 1)
          (check (header-value headers "Content-Type") => "application/x-s3-test")
          (check (header-value headers "X-Amz-Content-Sha256") => (hex-encode (sha256 data)))
          (check (and (string? timestamp)
                      (if (pregexp-match "^[0-9]{8}T[0-9]{6}Z$" timestamp) #t #f)) => #t)
          (check (and (string? authorization)
                      (if (pregexp-match
                           (string-append
                            "^AWS4-HMAC-SHA256 Credential=test-access-key/"
                            (substring timestamp 0 8)
                            "/us-east-1/s3/aws4_request,SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date,Signature=[0-9a-f]{64}$")
                           authorization) #t #f)) => #t))
        (check (bucket.exists? "nested/data.bin") => #t)
        (check (bucket.get "nested/data.bin") => data)
        (check (bucket.list-objects) => ["nested/data.bin"])
        (check-exception (client.delete-bucket! "objects") s3-client-error?)
        (bucket.copy-to! "objects/nested/data.bin" "copy.bin")
        (let* ((request (last-request))
               (headers (vector-ref request 2)))
          (check (vector-ref request 0) => "PUT")
          (check (vector-ref request 1) => "/objects/copy.bin")
          (check (vector-ref request 3) => '#u8())
          (check (header-value headers "X-Amz-Copy-Source") => "objects/nested/data.bin")
          (check (header-value headers "X-Amz-Content-Sha256") => (hex-encode (sha256 '#u8())))
          (check (if (string-contains (header-value headers "Authorization")
                                     "SignedHeaders=host;x-amz-content-sha256;x-amz-copy-source;x-amz-date,")
                   #t #f) => #t))
        (check (bucket.get "copy.bin") => data)
        (check (bucket.list-objects) => ["copy.bin" "nested/data.bin"])
        (check-exception (bucket.copy-to! "objects/missing" "bad-copy") s3-client-error?)
        (check (bucket.exists? "bad-copy") => #f)
        (check-exception (bucket.get "missing") s3-client-error?)
        (bucket.put! "empty" '#u8())
        (check (header-value (vector-ref (last-request) 2) "Content-Type")
               => "application/octet-stream")
        (check (bucket.get "empty") => '#u8())
        (bucket.delete! "empty")
        (bucket.delete! "copy.bin")
        (bucket.delete! "nested/data.bin")
        (bucket.delete! "nested/data.bin")
        (check (bucket.exists? "nested/data.bin") => #f)
        (check (bucket.list-objects) => [])
        (client.delete-bucket! "objects")))

    (test-case "non-success responses raise S3ClientError"
      (using (client (test-client) : S3Client)
        (check-exception (client.bucket-exists? "forbidden") s3-client-error?)
        (check-exception (client.create-bucket! "forbidden") s3-client-error?)))))
