;;; -*- Gerbil -*-
;;; © gerbil contributors
;;; AWS S3 client — authenticated bucket and object requests.

(import :std/crypto/digest
        :std/encoding/hex
        :std/error
        :std/interface
        :std/net/http/client
        :std/net/url
        :std/time/date
        ./interface
        ./response
        ./sigv4)
(export s3-client
        s3-client-error?)

(defstruct s3-client-impl
  ((endpoint    :- URL)
   (access-key  : :string)
   (secret-key  : :string)
   (region      : :string)
   (path-style? : :boolean)
   (this        :- S3Client))
  final: #t)

(defstruct bucket
  ((client :- s3-client-impl)
   (name   : :string)
   (region : :string))
  final: #t)

(deferror-class (S3ClientError Error) () s3-client-error?)

(defraise/context (raise-s3-error where message irritants ...)
  (S3ClientError message irritants: [irritants ...]))

(def empty-sha256 (sha256 '#u8()))

(def (parse-s3-endpoint (endpoint : :string))
  => URL
  (using (url (URL endpoint) :- URL)
    (unless (member url.proto '("http" "https"))
      (raise-s3-error s3-client "Unsupported endpoint protocol" url.proto))
    (unless (and (equal? url.path "/") (not url.query))
      (raise-s3-error s3-client
                      "Endpoint must not include a path or query"
                      endpoint))
    url))

(def (s3-client
      endpoint: (endpoint : :string := "https://s3.amazonaws.com")
      access-key: (access-key :? :string := (getenv "AWS_ACCESS_KEY_ID" #f))
      secret-key: (secret-key :? :string := (getenv "AWS_SECRET_KEY" #f))
      region: (region : :string := (getenv "AWS_DEFAULT_REGION" "us-east-1"))
      path-style: (path-style? : :boolean := #f))
  => S3Client
  (unless access-key
    (raise-s3-error s3-client "Must provide access key" "access-key"))
  (unless secret-key
    (raise-s3-error s3-client "Must provide secret key" "secret-key"))
  (using (client (make-s3-client-impl (parse-s3-endpoint endpoint)
                                    access-key secret-key region path-style? #f)
                 :- s3-client-impl)
    (set! client.this (S3Client client))
    client.this))

(def (make-client-bucket (client : s3-client-impl) (name : :string))
  => S3Bucket
  (S3Bucket (make-bucket client name client.region)))

(defmethod {list-buckets s3-client-impl}
  (lambda (self)
    (let (request (s3-request/error self verb: 'GET))
      (map (lambda (name) (make-client-bucket self name))
           (s3-bucket-names (s3-response-root (Request-content request))))))
  interface: S3Client)

(defmethod {create-bucket! s3-client-impl}
  (lambda (self bucket-name)
    (let (request
          (s3-request/error self verb: 'PUT bucket: bucket-name))
      (Request-close request)
      (make-client-bucket self bucket-name)))
  interface: S3Client)

(defmethod {get-bucket s3-client-impl}
  (lambda (self bucket-name)
    (if (self.this.bucket-exists? bucket-name)
      (make-client-bucket self bucket-name)
      (raise-s3-error s3-client-impl::get-bucket
                      "Bucket does not exist"
                      bucket-name)))
  interface: S3Client)

(defmethod {delete-bucket! s3-client-impl}
  (lambda (self bucket-name)
    (when (self.this.bucket-exists? bucket-name)
      (let (request
            (s3-request/error self verb: 'DELETE bucket: bucket-name))
        (Request-close request)))
    (void))
  interface: S3Client)

(defmethod {bucket-exists? s3-client-impl}
  (lambda (self bucket-name)
    (let* ((request (s3-request self verb: 'HEAD bucket: bucket-name))
           (status (Request-status request)))
      (cond
       ((fx= status 200)
        (Request-close request)
        #t)
       ((fx= status 404)
        (Request-close request)
        #f)
       (else
        (with-request-error request)
        #f))))
  interface: S3Client)

(defmethod {list-objects bucket}
  (lambda (self)
    (let (request
          (s3-request/error self.client verb: 'GET bucket: self.name))
      (s3-object-keys (s3-response-root (Request-content request)))))
  interface: S3Bucket)

(defmethod {get bucket}
  (lambda (self key)
    (let (request
          (s3-request/error self.client
            verb: 'GET
            bucket: self.name
            path: (string-append "/" key)))
      (Request-content request)))
  interface: S3Bucket)

(defmethod {exists? bucket}
  (lambda (self key)
    (let* ((request
            (s3-request self.client
             verb: 'HEAD
             bucket: self.name
             path: (string-append "/" key)))
           (status (Request-status request)))
      (cond
       ((fx= status 200)
        (Request-close request)
        #t)
       ((fx= status 404)
        (Request-close request)
        #f)
       (else
        (with-request-error request)
        #f))))
  interface: S3Bucket)

(defmethod {put! bucket}
  (lambda (self key data
                content-type: content-type)
    (let (request
          (s3-request/error self.client
            verb: 'PUT
            bucket: self.name
            path: (string-append "/" key)
            body: data
            content-type: content-type))
      (Request-close request)
      (void)))
  interface: S3Bucket)

(defmethod {delete! bucket}
  (lambda (self key)
    (let (request
          (s3-request/error self.client
            verb: 'DELETE
            bucket: self.name
            path: (string-append "/" key)))
      (Request-close request)
      (void)))
  interface: S3Bucket)

(defmethod {copy-to! bucket}
  (lambda (self source destination)
    (let* ((request
            (s3-request self.client
             verb: 'PUT
             bucket: self.name
             path: (string-append "/" destination)
             extra-headers: (list (cons "x-amz-copy-source" source))))
           (status (Request-status request))
           (status-line (Request-status-line request))
           (error-code
            (s3-response-error-code
             (s3-response-root (Request-content request)))))
      (cond
       (error-code
        (raise-s3-error bucket::copy-to!
                        "Unable to perform server-side copy"
                        error-code
                        status-line))
       ((or (fx< status 200) (fx>= status 300))
        (raise-s3-error bucket::copy-to! status-line status))
       (else
        (void)))))
  interface: S3Bucket)

(@implement S3Client s3-client-impl)
(@implement S3Bucket bucket)

(def (s3-request-host (self : s3-client-impl) (bucket :? :string))
  => :string
  (let (endpoint-host self.endpoint.host)
    (if (and bucket (not self.path-style?))
      (string-append bucket "." endpoint-host)
      endpoint-host)))

(def (s3-request-path (self : s3-client-impl)
                      (bucket :? :string)
                      (path : :string))
  => :string
  (unless (and (fx> (string-length path) 0)
               (char=? (string-ref path 0) #\/))
    (raise-s3-error s3-request
                    "Request path must begin with /"
                    path))
  (if (and bucket self.path-style?)
    (if (equal? path "/")
      (string-append "/" bucket)
      (string-append "/" bucket path))
    path))

(def (s3-request-url (self : s3-client-impl)
                     (host : :string)
                     (path : :string)
                     (query : :string))
  => URL
  (URL (string-append self.endpoint.proto "://" host path
                      (if (string-empty? query)
                        ""
                        (string-append "?" query)))))

(def (s3-request (self : s3-client-impl)
                 verb: (verb : :symbol := 'GET)
                 bucket: (bucket :? :string := #f)
                 path: (path : :string := "/")
                 query: (query : :list := [])
                 body: (body : :u8vector := '#u8())
                 extra-headers: (extra-headers : :list := [])
                 content-type: (content-type :? :string := #f))
  => Request
  (when (and (fx> (u8vector-length body) 0)
             (not content-type))
    (raise-s3-error s3-request
                    "Content type is required for a non-empty body"))
  (let* ((now (current-date))
         (timestamp (date->string now "%Y%m%dT%H%M%SZ"))
         (scope-date (date->string now "%Y%m%d"))
         (scope (string-append scope-date "/" self.region "/s3"))
         (hash (if (fxzero? (u8vector-length body))
                 empty-sha256
                 (sha256 body)))
         (host (s3-request-host self bucket))
         (request-path (s3-request-path self bucket path))
         (query-string (aws4-canonical-query-string query))
         (headers
          (append
           (list (cons "Host" host)
                 (cons "x-amz-date" timestamp)
                 (cons "x-amz-content-sha256" (hex-encode hash)))
           (if content-type
             (list (cons "Content-Type" content-type))
             [])
           extra-headers))
         (canonical-request
          (aws4-canonical-request
           verb: verb
           uri: request-path
           query: query
           headers: headers
           hash: hash))
         (authorization
          (aws4-auth scope canonical-request timestamp headers
                     self.secret-key self.access-key))
         ;; The HTTP client emits Host from the URL; do not duplicate it.
         (wire-headers
          (cons (cons "Authorization" authorization)
                (filter (lambda (header)
                          (not (string-ci=? (car header) "Host")))
                        headers)))
         (url (s3-request-url self host request-path query-string)))
    (case verb
      ((GET)
       (http-get url headers: wire-headers body: body))
      ((PUT)
       (http-put url headers: wire-headers body: body))
      ((DELETE)
       (http-delete url headers: wire-headers body: body))
      ((HEAD)
       (http-head url headers: wire-headers body: body))
      (else
       (raise-s3-error s3-request
                       "Unsupported request method"
                       verb)))))

(defrule (s3-request/error self args ...)
  (with-request-error (s3-request self args ...)))

(def (with-request-error (request : Request))
  => Request
  (let ((status (Request-status request))
        (status-line (Request-status-line request)))
    (if (and (fx>= status 200) (fx< status 300))
      request
      (begin
        (Request-close request)
        (raise-s3-error s3-request status-line status)))))
