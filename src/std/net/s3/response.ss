;;; -*- Gerbil -*-
;;; © gerbil contributors
;;; S3 response bodies: bucket names, object keys and error codes read from
;;; typed XML. Internal to the client; not re-exported by :std/net/s3.

(import :std/error
        :std/text/markup/xml/types
        :std/text/markup/xml/reader)
(export s3-response-root
        s3-bucket-names
        s3-object-keys
        s3-response-error-code)

;;; S3 responses use either namespace; the client accepts both.
(def s3-namespace-uri "http://s3.amazonaws.com/doc/2006-03-01/")
(def s3-doc-namespace-uri "http://doc.s3.amazonaws.com/2006-03-01")

;;; The document element of a response body, decoded as UTF-8 unless its XML
;;; declaration names another encoding.
(def (s3-response-root (content : :u8vector)) => XMLElement
  (using (doc (read-xml content keep-space?: #t) :- XMLDocument)
    doc.root))

(def (s3-name? (name  : XMLName)
               (local : :string))
  => :boolean
  (and (string=? name.local local)
       (or (string=? name.uri s3-namespace-uri)
           (string=? name.uri s3-doc-namespace-uri))))

(def (unqualified-name? (name  : XMLName)
                        (local : :string))
  => :boolean
  (and (string=? name.local local)
       (string-empty? name.uri)))

;;; The first element among nodes and their descendants, in document order,
;;; whose name satisfies (name? name local), or #f.
(def (find-element (nodes : :list)
                   (name? : :procedure)
                   (local : :string))
  => (Maybe XMLElement)
  (let find ((nodes nodes))
    (match nodes
      ([node . rest]
       (if (XMLElement? node)
         (using (el node :- XMLElement)
           (if (name? el.name local)
             el
             (or (find el.children)
                 (find rest))))
         (find rest)))
      (else #f))))

;;; The text of el's first child, the value the SXML client read with cadr;
;;; an element without text is a malformed response.
(def (element-text (el : XMLElement)) => :string
  (match el.children
    ([(? XMLText? text) . _]
     (using (text :- XMLText)
       text.data))
    (else
     (raise-io-error element-text "S3 response element without text"
                     el.name.local))))

;;; The Name of each Bucket in the first Buckets element; #f for a Bucket
;;; without a Name.
(def (s3-bucket-names (root : XMLElement)) => :list
  (using (buckets (find-element [root] s3-name? "Buckets") :? XMLElement)
    (if buckets
      (map (lambda ((bucket :- XMLElement))
             (let (name (find-element bucket.children s3-name? "Name"))
               (and name (element-text name))))
           (filter (lambda (node)
                     (and (XMLElement? node)
                          (using (el node :- XMLElement)
                            (s3-name? el.name "Bucket"))))
                   buckets.children))
      [])))

;;; The text of every Key element in document order, not searching inside a
;;; Key.
(def (s3-object-keys (root : XMLElement)) => :list
  (reverse
   (let collect ((nodes [root]) (keys []))
     (match nodes
       ([node . rest]
        (if (XMLElement? node)
          (using (el node :- XMLElement)
            (if (s3-name? el.name "Key")
              (collect rest (cons (element-text el) keys))
              (collect rest (collect el.children keys))))
          (collect rest keys)))
       (else keys)))))

;;; The Code of the response's Error element, or "Unknown" when it has none;
;;; #f without an Error element. Unqualified Error and Code elements come
;;; first, then those in an S3 namespace.
(def (s3-response-error-code (root : XMLElement)) => (Maybe :string)
  (using (err (or (find-element [root] unqualified-name? "Error")
                  (find-element [root] s3-name? "Error"))
              :? XMLElement)
    (and err
         (let (code (or (find-element err.children unqualified-name? "Code")
                        (find-element err.children s3-name? "Code")))
           (if code
             (element-text code)
             "Unknown")))))
