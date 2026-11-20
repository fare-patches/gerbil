;;; -*- Gerbil -*-
;;; © gerbil contributors
;;; S3 response extraction — offline fixtures for list and error responses.

(import :std/error
        :std/test
        :std/text/markup/xml/reader
        ./response)
(export response-test)

(def s3-uri "http://s3.amazonaws.com/doc/2006-03-01/")
(def s3-doc-uri "http://doc.s3.amazonaws.com/2006-03-01")

(def (root-of (body : :string))
  (s3-response-root (string->utf8 body)))

(def (keys-of (body : :string))
  (s3-object-keys (root-of body)))

(def (error-code-of (body : :string))
  (s3-response-error-code (root-of body)))

(def list-empty
  (string-append
   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
   "<ListBucketResult xmlns=\"" s3-uri "\">"
   "<Name>bucket</Name><Prefix></Prefix><KeyCount>0</KeyCount>"
   "<MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>"
   "</ListBucketResult>"))

(def list-one
  (string-append
   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
   "<ListBucketResult xmlns=\"" s3-uri "\">"
   "<Name>bucket</Name><Prefix></Prefix><Marker></Marker>"
   "<MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>"
   "<Contents><Key>data/2020/01/one.jpg</Key>"
   "<LastModified>2024-05-19T12:37:22.000Z</LastModified>"
   "<ETag>&quot;afd53bc49330e3c8cdb2d302ba6c004d&quot;</ETag><Size>34693647</Size>"
   "<Owner><ID>75aa57f09aa0c8ca</ID><DisplayName>owner</DisplayName></Owner>"
   "<StorageClass>STANDARD</StorageClass></Contents>"
   "</ListBucketResult>"))

;;; ListObjectsV2, indented, truncated, with common prefixes.
(def list-many-truncated
  (string-append
   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
   "<ListBucketResult xmlns=\"" s3-uri "\">\n"
   "  <Name>bucket</Name>\n"
   "  <Prefix>logs/</Prefix>\n"
   "  <Delimiter>/</Delimiter>\n"
   "  <ContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=</ContinuationToken>\n"
   "  <NextContinuationToken>2uePfjXl8kmBYcFh4wP6Hx/yRe7f0SDK=</NextContinuationToken>\n"
   "  <KeyCount>4</KeyCount>\n"
   "  <MaxKeys>3</MaxKeys>\n"
   "  <IsTruncated>true</IsTruncated>\n"
   "  <Contents>\n    <Key>logs/a.log</Key>\n    <Size>1</Size>\n  </Contents>\n"
   "  <Contents>\n    <Key>logs/b &amp; c.log</Key>\n    <Size>2</Size>\n  </Contents>\n"
   "  <Contents>\n    <Key><![CDATA[logs/<d>.log]]></Key>\n    <Size>3</Size>\n  </Contents>\n"
   "  <CommonPrefixes>\n    <Prefix>logs/2024/</Prefix>\n  </CommonPrefixes>\n"
   "</ListBucketResult>\n"))

(def list-non-ascii
  (string-append
   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
   "<ListBucketResult xmlns=\"" s3-uri "\"><Name>bucket</Name>"
   "<Contents><Key>λ/δοκιμή.txt</Key></Contents>"
   "<Contents><Key>日本語/ファイル.jpg</Key></Contents>"
   "<Contents><Key>emoji-😀-&#x263A;</Key></Contents>"
   "<Contents><Key>café</Key></Contents>"
   "</ListBucketResult>"))

(def list-buckets-doc-namespace
  (string-append
   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
   "<ListAllMyBucketsResult xmlns=\"" s3-doc-uri "\">"
   "<Owner><ID>75aa57f09aa0c8ca</ID><DisplayName>owner</DisplayName></Owner>"
   "<Buckets>"
   "<Bucket><Name>alpha</Name><CreationDate>2024-01-01T00:00:00.000Z</CreationDate></Bucket>"
   "<Bucket><Name>βeta</Name><CreationDate>2024-01-02T00:00:00.000Z</CreationDate></Bucket>"
   "</Buckets></ListAllMyBucketsResult>"))

(def error-unqualified
  (string-append
   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
   "<Error><Code>NoSuchKey</Code><Message>The resource you requested does not exist</Message>"
   "<Key>missing</Key><RequestId>4442587FB7D0A2F9</RequestId></Error>"))

(def (error-qualified uri)
  (string-append "<s3:Error xmlns:s3=\"" uri "\"><s3:Code>AccessDenied</s3:Code>"
                 "<s3:Message>Access Denied</s3:Message></s3:Error>"))

(def response-test
  (test-suite "test :std/net/s3 response extraction"
    (test-case "list responses with 0, 1 and many keys"
      (check (keys-of list-empty) => [])
      (check (keys-of (string-append "<ListBucketResult xmlns=\"" s3-uri "\">"
                                     "<Contents><Key> </Key></Contents></ListBucketResult>"))
             => [" "])
      (check (keys-of list-one) => ["data/2020/01/one.jpg"])
      (check (keys-of list-many-truncated)
             => ["logs/a.log" "logs/b & c.log" "logs/<d>.log"]))

    (test-case "keys are decoded as UTF-8 or the declared encoding"
      (check (keys-of list-non-ascii)
             => ["λ/δοκιμή.txt" "日本語/ファイル.jpg" "emoji-😀-☺" "café"])
      (check (s3-object-keys
              (s3-response-root
               (u8vector-append
                (string->utf8
                 (string-append "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>"
                                "<ListBucketResult xmlns=\"" s3-uri "\"><Contents><Key>caf"))
                (u8vector #xE9)
                (string->utf8 "</Key></Contents></ListBucketResult>"))))
             => ["café"]))

    (test-case "keys in either S3 namespace, by URI and local name"
      (for-each
       (lambda (uri)
         (check (keys-of (string-append "<ListBucketResult xmlns=\"" uri "\">"
                                        "<Contents><Key>k1</Key></Contents></ListBucketResult>"))
                => ["k1"])
         (check (keys-of (string-append "<p:ListBucketResult xmlns:p=\"" uri "\" xmlns:s3=\"urn:other\">"
                                        "<s3:Key>other</s3:Key><Key>unqualified</Key>"
                                        "<p:Contents><p:Key>k2</p:Key></p:Contents>"
                                        "<p:Contents><Key xmlns=\"urn:other\">other</Key>"
                                        "<p:Key>k3</p:Key></p:Contents>"
                                        "</p:ListBucketResult>"))
                => ["k2" "k3"]))
       [s3-uri s3-doc-uri])
      (check (keys-of "<ListBucketResult><Contents><Key>k</Key></Contents></ListBucketResult>")
             => []))

    (test-case "bucket names from the first Buckets element"
      (check (s3-bucket-names (root-of list-buckets-doc-namespace)) => ["alpha" "βeta"])
      (check (s3-bucket-names
              (root-of (string-append "<ListAllMyBucketsResult xmlns=\"" s3-uri "\">"
                                      "<Buckets><Bucket><Name>one</Name></Bucket><Bucket/>"
                                      "<Other><Bucket><Name>nested</Name></Bucket></Other>"
                                      "</Buckets></ListAllMyBucketsResult>")))
             => ["one" #f])
      (check (s3-bucket-names (root-of "<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>"))
             => [])
      (check (s3-bucket-names (root-of list-one)) => []))

    (test-case "error codes from unqualified and qualified Error elements"
      (check (error-code-of error-unqualified) => "NoSuchKey")
      (check (error-code-of (error-qualified s3-uri)) => "AccessDenied")
      (check (error-code-of (error-qualified s3-doc-uri)) => "AccessDenied")
      (check (error-code-of "<Error><Message>no code</Message></Error>") => "Unknown")
      (check (error-code-of "<Error xmlns=\"urn:other\"><Code>X</Code></Error>") => #f)
      (check (error-code-of "<CopyObjectResult><ETag>e</ETag></CopyObjectResult>") => #f)
      (check (error-code-of "<CopyObjectResult><Error><Code>Nested</Code></Error></CopyObjectResult>")
             => "Nested")
      ;; Unqualified Error and Code elements win over earlier qualified ones.
      (check (error-code-of
              (string-append "<r xmlns:s3=\"" s3-uri "\">"
                             "<s3:Error><s3:Code>Qualified</s3:Code></s3:Error>"
                             "<Error><s3:Code>S3</s3:Code><Code>Plain</Code></Error></r>"))
             => "Plain"))

    (test-case "malformed responses raise"
      (check-exception (root-of "<broken>") xml-parse-error?)
      (check-exception (root-of "") xml-parse-error?)
      (check-exception (keys-of (string-append "<ListBucketResult xmlns=\"" s3-uri "\">"
                                               "<Contents><Key></Key></Contents></ListBucketResult>"))
                       io-error?)
      (check-exception (error-code-of "<Error><Code/></Error>") io-error?))))
