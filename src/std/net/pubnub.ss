;;; -*- Gerbil -*-
;;; (C) fare
;;; PubNub Real-time Push Cloud API
;; Based on the python3 3.9.0 client from https://github.com/pubnub/python branch master_3x
;; TODO: test it!!!!
package: std/net

(export
  pubnub)

(import
  :gerbil/gambit/bits
  :gerbil/gambit/bytes
  :gerbil/gambit/os
  :gerbil/gambit/ports
  (only-in :gerbil/gambit/random random-integer)
  :gerbil/gambit/threads
  :std/crypto/cipher
  :std/crypto/digest
  :std/crypto/etc
  :std/error
  :std/format
  :std/logger
  :std/misc/queue
  :std/misc/string
  :std/misc/uuid
  :std/net/request
  :std/net/uri
  :std/os/socket
  :std/srfi/1 ;; list
  :std/srfi/13 ;; string
  :std/srfi/19 ;; time
  :std/sort
  :std/sugar
  :std/text/base64
  :std/text/json
  :std/text/hex
  :std/text/utf8)

;; TODO: pass these options to the connection pool manager
(def default-socket-options
  '(;; Send first keepalive packet 200 seconds after last data packet
    (IPPROTO_TCP TCP_KEEPIDLE 200)
    ;; Resend keepalive packets every second, when unanswered
    (IPPROTO_TCP TCP_KEEPINTVL 1)
    ;; Close the socket after 5 unanswered keepalive packets
    (IPPROTO_TCP TCP_KEEPCNT 5)))

(def (get-data-for-user data)
  (if (and (hash-table? data) (hash-key? data "message") (hash-key? data "payload"))
    (hash ("message" (hash-ref data "message"))
          ("payload" (hash-ref data "payload")))
    data))

(def (pad msg (block-size 16))
  (let* ((padding-length (- block-size (modulo (u8vector-length msg) block-size)))
         (padding-vector (make-u8vector padding-length padding-length)))
    (u8vector-append msg padding-vector)))

(def (depad msg)
  (subu8vector msg 0 (u8vector-ref (- (u8vector-length msg) 1))))

(def (get-secret key)
  (hexlify (sha256 key)))

(def ::cipher-type cipher::aes-128-cbc)
(def ::initial-16-bytes (@bytes "0123456789012345"))

(def (%encrypt key msg)
  (base64-encode
   (encrypt-u8vector
    (make-cipher ::cipher-type)
    (string->utf8 (get-secret key))
    ::initial-16-bytes
    (pad (string->utf8 msg)))))

(def (%decrypt key msg)
  (utf8->string
   (depad
    (encrypt-u8vector
     (make-cipher ::cipher-type)
     (string->utf8 (get-secret key))
     ::initial-16-bytes
     (base64-decode msg)))))

(defclass pubnub
  (publish-key ;; : String
   subscribe-key ;; : String
   secret-key ;; : (Or String '#f) ; default #f (no encryption)
   cipher-key ;; : (Or String '#f) ; default #f (no encryption)
   auth-key ;; : (Or String '#f) ; default #f (used with Pubnub Access Manager i.e. PAM)
   ssl-on ;; : Bool ; default #f
   origin ;; : String ; default "pubsub.pubnub.com"
   uuid ;; : (Or String '#f) ; default #f
   ;; private
   state ;; (hash)
   http-debug
   u
   %encode-pam
   subscriptions
   subscription-groups
   timetoken
   last-timetoken
   accept-encoding
   sub-receiver
   connect
   tt-mutex
   channel-list-mutex
   channel-group-list-mutex
   heartbeat
   heartbeat-interval
   heartbeat-running
   heartbeat-stop-flag
   abort-heartbeat
   heartbeat-callback
   heartbeat-error)
  constructor: init!)

;; TODO: find how to make next-method work for pubnub-core-async
(defmethod {init! pubnub}
  (lambda (self
           publish-key: (publish-key #f)
           subscribe-key: (subscribe-key #f)
           secret-key: (secret-key #f)
           cipher-key: (cipher-key #f)
           auth-key: (auth-key #f)
           ssl-on: (ssl-on #f)
           origin: (origin "pubsub.pubnub.com")
           uuid: (uuid #f))
  (set! (@ self publish-key) publish-key)
  (set! (@ self subscribe-key) subscribe-key)
  (set! (@ self secret-key) secret-key)
  (set! (@ self cipher-key) cipher-key)
  (set! (@ self auth-key) auth-key)
  (set! (@ self ssl-on) ssl-on)
  (set! (@ self origin) (format "~s://~s" (if ssl-on "https" "http") origin))
  (set! (@ self uuid) (or uuid (uuid->string (random-uuid))))
  (assert! (string? uuid) "uuid must be a string")
  (set! (@ self state) (hash))
  (set! (@ self http-debug) #f)
  (set! (@ self u) #f)
  (set! (@ self subscriptions) (hash))
  (set! (@ self subscription-groups) (hash))
  (set! (@ self timetoken) 0)
  (set! (@ self last-timetoken) 0)
  (set! (@ self accept-encoding) "gzip")
  (set! (@ self sub-receiver) #f)
  (set! (@ self connect) void)
  (set! (@ self tt-mutex) (make-mutex))
  (set! (@ self channel-list-mutex) (make-mutex))
  (set! (@ self channel-group-list-mutex) (make-mutex))
  (set! (@ self heartbeat) 0)
  (set! (@ self heartbeat-interval) 0)
  (set! (@ self heartbeat-running) #f)
  (set! (@ self heartbeat-stop-flag) #f)
  (set! (@ self abort-heartbeat) void)
  (set! (@ self heartbeat-callback) void)
  (set! (@ self heartbeat-error) void)))

(def pubnub-version "0.0.1") ;; based on the python client version 3.9.0
(def pubnub-sdk (string-append "PubNub-Gerbil/" pubnub-version))

(def ::digest-type digest::sha256)

(defmethod {%pam-sign pubnub}
  (lambda (self msg)
    ;; NB: the python version wraps that in (quote ... safe="=") which looks like a NOP to me,
    ;; since the only characters in a urlsafe base64-string are alphanumerics and -_=
    ;; whereas the quote function lets them all go through (because safe="=") (and also .).
    (u8vector->base64-string
     (sha256 ;; TODO: introduce primitives that without consing the appended vector
      (u8vector-append
       (string->utf8 (@ self key))
       (string->utf8 msg))))))

(defmethod {%pam-auth pubnub}
  (lambda (self query apicode: (apicode 0) callback: (callback #f) error: (error #f))
    ;; Global Grant?
    (if (eqv? #f (hash-ref query "auth" #t))
      (hash-remove! query "auth"))
    (if (eqv? #f (hash-ref query "channel" #t))
      (hash-remove! query "channel"))
    (if (eqv? #f (hash-ref query "channel-group" #t))
      (hash-remove! query "channel-group"))
    {%request
     self
     ["v1" "auth" (if apicode "audit" "grant") "sub-key" (@ self subscribe-key)]
     query
     callback: {%wrap-callback self callback}
     error: {%wrap-callback self error}
     encoder-map: (hash ("signature" (@ self %encode-pam)))}))

;; Method for granting permissions.
;;
;; This function establishes subscribe and/or write permissions for
;; PubNub Access Manager (PAM) by setting the read or write attribute
;; to true. A grant with read or write set to false (or not included)
;; will revoke any previous grants with read or write set to true.
;;
;; Permissions can be applied to any one of three levels:
;;     1. Application level privileges are based on subscribe-key applying
;;        to all associated channels.
;;     2. Channel level privileges are based on a combination of
;;        subscribe-key and channel name.
;;     3. User level privileges are based on the combination of
;;        subscribe-key, channel and auth-key.
;;
;; Args:
;;     channel:    (string) (optional)
;;                 Specifies channel name to grant permissions to.
;;                 If channel/channel-group is not specified, the grant
;;                 applies to all channels associated with the
;;                 subscribe-key. If auth-key is not specified, it is
;;                 possible to grant permissions to multiple channels
;;                 simultaneously by specifying the channels
;;                 as a comma separated list.
;;     channel-group:    (string) (optional)
;;                 Specifies channel group name to grant permissions to.
;;                 If channel/channel-group is not specified, the grant
;;                 applies to all channels associated with the
;;                 subscribe-key. If auth-key is not specified, it is
;;                 possible to grant permissions to multiple channel
;;                 groups simultaneously by specifying the channel groups
;;                 as a comma separated list.
;;
;;     auth-key:   (string) (optional)
;;                 Specifies auth-key to grant permissions to.
;;                 It is possible to specify multiple auth-keys as comma
;;                 separated list in combination with a single channel
;;                 name. If auth-key is provided as the special-case
;;                 value "null" (or included in a comma-separated list,
;;                 eg. "null,null,abc"), a new auth-key will be generated
;;                 and returned for each "null" value.
;;
;;     read:       (boolean) (default: #t)
;;                 Read permissions are granted by setting to #t.
;;                 Read permissions are removed by setting to #f.
;;
;;     write:      (boolean) (default: #t)
;;                 Write permissions are granted by setting to true.
;;                 Write permissions are removed by setting to false.
;;
;;     manage:      (boolean) (default: #t)
;;                 Manage permissions are granted by setting to true.
;;                 Manage permissions are removed by setting to false.

;;     ttl:        (int) (default: 1440 i.e 24 hrs)
;;                 Time in minutes for which granted permissions are
;;                 valid. Max is 525600, Min is 1.
;;                 Setting ttl to 0 will apply the grant indefinitely.

;;     callback:   (function) (optional)
;;                 A callback method can be passed to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or tornado
;;
;;     error:      (function) (optional)
;;                 An error method can be passed to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or tornado
;;
;; Returns:
;;     Returns a hash-table in sync mode i.e. when callback argument is not
;;     given
;;     The hash-table returned contains values with keys 'message' and 'payload'
;;
;;     Sample Response:
;;     {
;;         "message":"Success",
;;         "payload":{
;;             "ttl":5,
;;             "auths":{
;;                 "my-ro-authkey":{"r":1,"w":0}
;;             },
;;             "subscribe-key":"my-subkey",
;;             "level":"user",
;;             "channel":"my-channel"
;;         }
;;     }
(def (grant
      pubnub
      channel: (channel #f)
      channel-group: (channel-group #f)
      auth-key: (auth-key #f)
      read: (read #f)
      write: (write #f)
      manage: (manage #f)
      ttl: (ttl 5)
      callback: (callback #f)
      error: (error #f))

  {%pam-auth
   (hash
    ("channel" channel)
    ("channel-group" channel-group)
    ("auth" auth-key)
    ("r" (if read 1 0))
    ("w" (if write 1 0))
    ("m" (if manage 1 0))
    ("ttl" ttl)
    ("pnsdk" pubnub-sdk))
   callback: callback
   error: error})

;; Method for revoking permissions.
;;
;; Args:
;;     channel:    (string) (optional)
;;                 Specifies channel name to revoke permissions to.
;;                 If channel/channel-group is not specified, the revoke
;;                 applies to all channels associated with the
;;                 subscribe-key. If auth-key is not specified, it is
;;                 possible to grant permissions to multiple channels
;;                 simultaneously by specifying the channels as a comma
;;                 separated list.
;;
;;     channel-group:    (string) (optional)
;;                 Specifies channel group name to revoke permissions to.
;;                 If channel/channel-group is not specified, the grant
;;                 applies to all channels associated with the
;;                 subscribe-key. If auth-key is not specified, it is
;;                 possible to revoke permissions to multiple channel
;;                 groups simultaneously by specifying the channel groups
;;                 as a comma separated list.
;;
;;     auth-key:   (string) (optional)
;;                 Specifies auth-key to revoke permissions to.
;;                 It is possible to specify multiple auth-keys as comma
;;                 separated list in combination with a single channel
;;                 name. If auth-key is provided as the special-case
;;                 value "null" (or included in a comma-separated list,
;;                 eg. "null,null,abc"), a new auth-key will be generated
;;                 and returned for each "null" value.
;;
;;     ttl:        (int) (default: 1440 i.e 24 hrs)
;;                 Time in minutes for which granted permissions are
;;                 valid.
;;                 Max is 525600 , Min is 1.
;;                 Setting ttl to 0 will apply the grant indefinitely.
;;
;;     callback:   (function) (optional)
;;                 A callback method can be passed to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;;     error:      (function) (optional)
;;                 An error method can be passed to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;; Returns:
;;     Returns a dict in sync mode i.e. when callback argument is not
;;     given.
;;     The dict returned contains values with keys 'message' and 'payload'
;;
;;     Sample Response:
;;     {
;;         "message":"Success",
;;         "payload":{
;;             "ttl":5,
;;             "auths":{
;;                 "my-authkey":{"r":0,"w":0}
;;             },
;;             "subscribe-key":"my-subkey",
;;             "level":"user",
;;             "channel":"my-channel"
;;         }
;;     }
(defmethod {revoke pubnub}
  (lambda (self
           channel: (channel #f)
           channel-group: (channel-group #f)
           auth-key: (auth-key #f)
           ttl: (ttl 1)
           callback: (callback #f)
           error: (error #f))
    {%pam-auth
     self
     (hash
      ("channel" channel)
      ("channel-group" channel-group)
      ("auth" auth-key)
      ("r" 0)
      ("w" 0)
      ("ttl" ttl)
      ("pnsdk" pubnub-sdk))
     callback: callback
     error: error}))

;; Method for fetching permissions from pubnub servers.
;;
;; This method provides a mechanism to reveal existing PubNub Access
;; Manager attributes for any combination of subscribe-key, channel
;; and auth-key.
;;
;; Args:
;;     channel:    (string) (optional)
;;                 Specifies channel name to return PAM
;;                 attributes optionally in combination with auth-key.
;;                 If channel/channel-group is not specified, results
;;                 for all channels associated with subscribe-key are
;;                 returned. If auth-key is not specified, it is possible
;;                 to return results for a comma separated list of
;;                 channels.
;;     channel-group:    (string) (optional)
;;                 Specifies channel group name to return PAM
;;                 attributes optionally in combination with auth-key.
;;                 If channel/channel-group is not specified, results
;;                 for all channels associated with subscribe-key are
;;                 returned. If auth-key is not specified, it is possible
;;                 to return results for a comma separated list of
;;                 channels.
;;
;;     auth-key:   (string) (optional)
;;                 Specifies the auth-key to return PAM attributes for.
;;                 If only a single channel is specified, it is possible
;;                 to return results for a comma separated list of
;;                 auth-keys.
;;
;;     callback:   (function) (optional)
;;                 A callback method can be passed to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;;     error:      (function) (optional)
;;                 An error method can be passed to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;; Returns:
;;     Returns a dict in sync mode i.e. when callback argument is not
;;     given
;;     The dict returned contains values with keys 'message' and 'payload'
;;
;;     Sample Response
;;     {
;;         "message":"Success",
;;         "payload":{
;;             "channels":{
;;                 "my-channel":{
;;                     "auths":{"my-ro-authkey":{"r":1,"w":0},
;;                     "my-rw-authkey":{"r":0,"w":1},
;;                     "my-admin-authkey":{"r":1,"w":1}
;;                 }
;;             }
;;         },
;;     }
;;
;; Usage:
;;      {audit pubnub channel: "my-channel"} ; Sync Mode
;;
(defmethod {audit pubnub}
  (lambda (self
           channel: (channel #f)
           channel-group: (channel-group #f)
           auth-key: (auth-key #f)
           callback: (callback #f)
           error: (error #f))
    {%pam-auth
     (hash
      ("channel" channel)
      ("channel-group" channel-group)
      ("auth" auth-key)
      ("pnsdk" pubnub-sdk))
     apicode: 1
     callback: callback
     error: error}))

;; Method for encrypting data.
;;
;; This method takes plaintext as input and returns encrypted data.
;; This need not be called directly as enncryption/decryption is
;; taken care of transparently by Pubnub class if cipher key is
;; provided at time of initializing pubnub object
;;
;; Args:
;;     message: Message to be encrypted.
;;
;; Returns:
;;     Returns encrypted message if cipher key is set
(defmethod {encrypt pubnub}
  (lambda (self message)
    (json-object->string
     (if (@ self cipher-key)
       (%encrypt (@ self cipher-key) (json-object->string message))
       message))))

;; Method for decrypting data.
;;
;; This method takes ciphertext as input and returns decrypted data.
;; This need not be called directly as enncryption/decryption is
;; taken care of transparently by Pubnub class if cipher key is
;; provided at time of initializing pubnub object
;;
;; Args:
;;     message: Message to be decrypted.
;;
;; Returns:
;;     Returns decrypted message if cipher key is set
(defmethod {decrypt pubnub}
  (lambda (self message)
    (if (@ self cipher-key)
      (%decrypt (@ self cipher-key) message)
      message)))

(def (%wrap-callback self (callback #f))
  (and callback
       (lambda (response)
         (when (@ self http-debug)
           ((@ self http-debug) response))
         (callback
          (if (hash-key? response "payload")
            (let ((callback-data (hash ("payload" (hash-ref response "payload")))))
              (when (hash-key? response "message")
                (hash-put! callback-data "message" (hash-ref response "message")))
              callback-data)
            response)))))

(defmethod {leave-channel pubnub}
  (lambda (self channel callback: (callback #f) error: (error #f))
    ;; Send leave
    {%request
     self
     ["v2" "presence"
      "sub_key" (@ self subscribe-key)
      "channel" channel
      "leave"]
     (hash
      ("auth" (@ self auth-key))
      ("pnsdk" pubnub-sdk)
      ("uuid" (@ self uuid)))
     callback: (%wrap-callback self callback)
     error: (%wrap-callback self error)}))

(defmethod {leave-group pubnub}
  (lambda (self channel-group callback: (callback #f) error: (error #f))
    ;; Send leave
    {%request
     self
     ["v2" "presence"
      "sub-key" (@ self subscribe-key)
      "channel" ","
      "leave"]
     (hash
      ("auth" (@ self auth-key))
      ("pnsdk" pubnub-sdk)
      ("channel-group" channel-group)
      ("uuid" (@ self uuid)))
     callback: (%wrap-callback self callback)
     error: (%wrap-callback self error)}))

;; Publishes data on a channel.
;;
;; The publish() method is used to send a message to all subscribers of
;; a channel. To publish a message you must first specify a valid
;; publish-key at initialization. A successfully published message is
;; replicated across the PubNub Real-Time Network and sent simultaneously
;; to all subscribed clients on a channel. Messages in transit can be
;; secured from potential eavesdroppers with SSL/TLS by setting ssl to
;; #t during initialization.
;;
;; Published messages can also be encrypted with AES-256 simply by
;; specifying a cipher-key during initialization.
;;
;; Args:
;;     channel:    (string)
;;                 Specifies channel name to publish messages to.
;;     message:    (string/int/double/dict/list)
;;                 Message to be published
;;     callback:   (optional)
;;                 A callback method can be passed to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;     error:      (optional)
;;                 An error method can be passed to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;; Returns:
;;     Sync Mode  : list
;;     Async Mode : None
;;
;;     The function returns the following formatted response:
;;
;;         [ Number, "Status", "Time Token"]
;;
;;     The output below demonstrates the response to a successful call:
;;
;;         [1,"Sent","13769558699541401"]
;;
;;
(defmethod {publish pubnub}
  (lambda (self
           channel
           message
           store: (store #t)
           replicate: (replicate #t)
           callback: (callback #f)
           error: (error #f))
    (let ((params
           (hash
            ("pnsdk" pubnub-sdk))))
      (when (@ self auth-key)
        (hash-put! params "auth" (@ self auth-key)))
      (unless store
        (hash-put! params "store" 0))
      (unless replicate
        (hash-put! params "replicate" "true"))
      {%request
       self
       ["publish" (@ self publish-key) (@ self subscribe-key) "0" channel "0"
        {encrypt self message}]
       params
       callback: (%wrap-callback self callback)
       error: (%wrap-callback self error)})))

(defmethod {fire pubnub}
  (lambda (self channel message callback: (callback #f) error: (error #f))
    {publish self channel message callback: callback error: error store: #f replicate: #f}))

(defmethod {mobile-gw-provision pubnub}
  (lambda (self
           device-id
           remove-device: (remove-device #f)
           callback: (callback #f)
           channel-to-add: (channel-to-add #f)
           channel-to-remove: (channel-to-remove #f)
           gw-type: (gw-type "apns")
           error: (error #f))
    ;; check allowed gw types
    (unless (member gw-type '("gcm" "apns" "mpns"))
      (error "Invalid gw-type"))
    (when (and remove-device (or channel-to-add channel-to-remove))
      (error "Can't add or remove channels while removing device"))
    {%request
     self
     `("v1" "push" "sub-key" (@ self subscribe-key) "devices" device-id
       ,@(if remove-device '("remove") '()))
     (hash
      ;; specific params
      ("add" channel-to-add)
      ("remove" channel-to-remove)
      ("type" gw-type)
      ;; default params
      ("auth" (@ self auth-key))
      ("pnsdk" pubnub-sdk))
     callback: (%wrap-callback self callback)
     error: (%wrap-callback self error)}))

;; Subscribe to presence events on a channel.
;;
;;    Only works in async mode
;;
;; Args:
;;     channel: Channel name ( string ) on which to listen for events
;;     callback: A callback method should be passed as parameter.
;;               If passed, the api works in async mode.
;;               Required argument when working with twisted or tornado.
;;     error: Optional variable.
;;             An error method can be passed as
;;             parameter. If set, the api works in async mode.
;;
;; Returns:
;;     None
;;
(defmethod {presence pubnub}
  (lambda (self
           channel
           callback
           error: (error #f)
           connect: (connect #f)
           disconnect: (disconnect #f)
           reconnect: (reconnect #f))
    {subscribe
     self
     (string-append channel "-pnpres")
     callback: callback
     error: error
     connect: connect
     disconnect: disconnect
     reconnect: reconnect}))

;; Is the channel or channel-group name one for presence events?
(def (presence-name? string) (string-suffix? "-pnpres" string))

;; Make a channel(-group) name into a presence name
(def (presence-name string) (string-append string "-pnpres"))

;; Remove the presence suffix from a name, if any
(def (unpresence-name string) (string-trim-suffix "-pnpres" string))

;; Subscribe to presence events on a channel group.
;;
;;    Only works in async mode
;;
;; Args:
;;     channel-group: Channel group name ( string )
;;     callback: A callback method should be passed to the method.
;;               If passed, the api works in async mode.
;;               Required argument when working with twisted or tornado.
;;     error: Optional variable. An error method can be passed as
;;             parameter.
;;               If passed, the api works in async mode.
;;
;; Returns:
;;     None
(defmethod {presence-group pubnub}
  (lambda (self
           channel-group
           callback
           error: (error #f)
           connect: (connect #f)
           disconnect: (disconnect #f)
           reconnect: (reconnect #f))
    {subscribe-group
     self
     (presence-name channel-group)
     callback: callback
     error: error
     connect: connect
     disconnect: disconnect
     reconnect: reconnect
     presence: callback}))


;; Get/Set state data.
;;
;; The state API is used to set key/value pairs specific to a subscriber
;; uuid.
;; State information is supplied as a dict of key/value pairs.
;;
;; Args:
;;     state:      (string) (optional)
;;                 Specifies the channel name to return occupancy
;;                 results. If channel is not provided, here-now will
;;                 return data for all channels.
;;
;;     uuid:       (string) (optional)
;;                 The subscriber uuid to set state for or get current
;;                 state from.
;;                 Default is current uuid.
;;
;;     channel:    (string) (optional)
;;                 Specifies the channel for which state is to be
;;                 set/get.
;;
;;     channel-group:    (string) (optional)
;;                 Specifies the channel-group for which state is to
;;                 be set/get.
;;
;;     callback:   (optional)
;;                 A callback method should be passed to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;;     error:      (optional)
;;                 Optional variable. An error method can be passed to
;;                 the method. If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;; Returns:
;;     Sync  Mode: Object
;;     Async Mode: None
;;
;;     Response Format:
;;
;;     The state API returns a JSON object containing key value pairs.
;;
;;     Example Response:
;;     {
;;       first   : "Robert",
;;       last    : "Plant",
;;       age     : 59,
;;       region  : "UK"
;;     }
;;
(defmethod {state pubnub}
  (lambda (self
           channel: (channel #f)
           channel-group: (channel-group #f)
           uuid: (uuid #f)
           state: (state #f)
           callback: (callback #f)
           error: (error #f))
    (def data
      (hash
       ("auth" (@ self auth-key))
       ("pnsdk" pubnub-sdk)))

    (when (and channel state
               (hash-get (@ self subscriptions) channel)
               (hash-get (hash-get (@ self subscriptions) channel) "subscribed"))
      (hash-put! (@ self state) channel state))

    (when (and channel-group state
               (hash-get (@ self subscription-groups) channel)
               (hash-get (hash-get (@ self subscription-groups) channel) "subscribed"))
      (hash-put! (@ self state) channel-group state)
      (hash-put! data "channel-group" channel-group)
      (set! channel ","))

    (unless uuid
      (set! uuid (@ self uuid)))

    (def urlcomponents
      `("v2" "presence"
        "sub-key" (@ self subscribe-key)
        "channel" channel
        "uuid" uuid
        ,@(if state
            (begin
              (hash-put! data "state" (json-object->string state))
              '("data"))
            '())))

    {%request
     self
     urlcomponents
     data
     callback: (%wrap-callback self callback)
     error: (%wrap-callback self error)}))

;; Get where now data.
;;
;; You can obtain information about the current list of a channels to
;; which a uuid is subscribed to by calling the where-now() function
;; in your application.
;;
;; Args:
;;
;;     uuid:       (optional)
;;                 Specifies the uuid to return channel list for.
;;                 Default is current uuid.
;;
;;     callback:   (optional)
;;                 A callback method should be passed to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;;     error:      (optional)
;;                 Optional variable. An error method can be passed
;;                 to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;; Returns:
;;     Sync  Mode: list
;;     Async Mode: None
;;
;;     Response Format:
;;
;;     The where-now() method returns a list of channels to which
;;     uuid is currently subscribed.
;;
;;     channels:["String","String", ... ,"String"] - List of Channels
;;     uuid is currently subscribed to.
;;
;;     Example Response:
;;     {
;;         "channels":
;;             [
;;                 "lobby",
;;                 "game01",
;;                 "chat"
;;             ]
;;     }
;;
(defmethod {where-now pubnub}
  (lambda (self uuid: (uuid #f) callback: (callback #f) error: (error #f))
    {%request
     self
     ["v2" "presence"
      "sub-key" (@ self subscribe-key)
      "uuid" (or uuid (@ self uuid))]
     (hash
      ("auth" (@ self auth-key))
      ("pnsdk" pubnub-sdk))
     callback: (%wrap-callback self callback)
     error: (%wrap-callback self error)}))


;; Get here now data.
;;
;; You can obtain information about the current state of a channel
;; including a list of unique user-ids currently subscribed to the
;; channel and the total occupancy count of the channel by calling
;; the here-now() function in your application.
;;
;;
;; Args:
;;     channel:       (string) (optional)
;;                    Specifies the channel name to return occupancy
;;                    results. If channel is not provided, here-now will
;;                    return data for all channels.
;;
;;     channel-group: (string) (optional)
;;                    Specifies the channel name to return occupancy
;;                    results. If channel is not provided, here-now will
;;                    return data for all channels.
;;
;;     callback:      (optional)
;;                    A callback method should be passed to the method.
;;                    If set, the api works in async mode.
;;                    Required argument when working with twisted or
;;                    tornado.
;;
;;     error:         (optional)
;;                    Optional variable. An error method can be passed
;;                    to the method.
;;                    If set, the api works in async mode.
;;                    Required argument when working with twisted or
;;                    tornado .
;;
;; Returns:
;;     Sync  Mode: list
;;     Async Mode: None
;;
;;     Response Format:
;;
;;     The here-now() method returns a list of uuid s currently
;;     subscribed to the channel.
;;
;;     uuids:["String","String", ... ,"String"] - List of UUIDs currently
;;     subscribed to the channel.
;;
;;     occupancy: Number - Total current occupancy of the channel.
;;
;;     Example Response:
;;     {
;;         occupancy: 4,
;;         uuids: [
;;             '123123234t234f34fq3dq',
;;             '143r34f34t34fq34q34q3',
;;             '23f34d3f4rq34r34rq23q',
;;             'w34tcw45t45tcw435tww3',
;;         ]
;;     }
;;
(defmethod {here-now pubnub}
  (lambda (self
           channel: (channel #f)
           channel-group: (channel-group #f)
           uuids: (uuids #t)
           state: (state #f)
           callback: (callback #f)
           error: (error #f))
    (def data
      (hash
       ("auth" (@ self auth-key))
       ("pnsdk" pubnub-sdk)))
    (when state
      (hash-put! data "state" 1))
    (unless uuids
      (hash-put! data "disable-uuids" 1))
    (when channel-group
      (hash-put! data "channel-group" channel-group))
    {%request
     self
     `("v2" "presence"
       "sub-key" (@ self subscribe-key)
       ,@(if (or channel channel-group)
           ["channel" (or channel ",")]
           []))
     data
     callback: (%wrap-callback self callback)
     error: (%wrap-callback self error)}))

;; This method fetches historical messages of a channel.
;;
;; PubNub Storage/Playback Service provides real-time access to an
;; unlimited history for all messages published to PubNub. Stored
;; messages are replicated across multiple availability zones in several
;; geographical data center locations. Stored messages can be encrypted
;; with AES-256 message encryption ensuring that they are not readable
;; while stored on PubNub's network.
;;
;; It is possible to control how messages are returned and in what order,
;; for example you can:
;;
;;     Return messages in the order newest to oldest (default behavior).
;;
;;     Return messages in the order oldest to newest by setting reverse
;;     to true.
;;
;;     Page through results by providing a start or end time token.
;;
;;     Retrieve a "slice" of the time line by providing both a start
;;     and end time token.
;;
;;     Limit the number of messages to a specific quantity using
;;     the count parameter.
;;
;; Args:
;;     channel:    (string)
;;                 Specifies channel to return history messages from
;;
;;     count:      (int) (default: 100)
;;                 Specifies the number of historical messages to return
;;
;;     callback:   (optional)
;;                 A callback method should be passed to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;;     error:      (optional)
;;                 An error method can be passed to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;; Returns:
;;     Returns a list in sync mode i.e. when callback argument is not
;;     given
;;
;;     Sample Response:
;;         [["Pub1","Pub2","Pub3","Pub4","Pub5"],
;;             13406746729185766,13406746845892666]
;;
(defmethod {history pubnub}
  (lambda (self
           channel
           count: (count 100)
           reverse: (reverse #f)
           start: (start #f)
           end: (end #f)
           include-token: (include-token #f)
           callback: (callback #f)
           error: (error #f))

    (def (%get-decrypted-history resp)
      (if (and (list? resp) (car resp) (@ self cipher-key))
        (map (lambda (msg) {decrypt self msg}) resp)
        resp))

    (def (%history-callback resp)
      (when callback
        (callback (%get-decrypted-history resp))))

    (def history-callback
      (and callback %history-callback))

    (def params
      (hash
       ("reverse" (if reverse "true" "false"))
       ("stringtoken" "true")
       ("include-token" (if include-token "true" "false"))
       ("count"
        (if (and count (or (> 1 count) (< 100 count)))
          (error "Message count should be between 1 and 100")
          (or count 100)))
       ("auth" (@ self auth-key))
       ("pnsdk" pubnub-sdk)))
    (when (and start (< 0 start))
      (hash-put! params "start" start))
    (when (and end (< 0 end))
      (hash-put! params "end" end))

    (%get-decrypted-history
     {%request
      self
      ["v2" "history" "sub-key" (@ self subscribe-key) "channel" channel]
      params
      callback: (%wrap-callback self callback)
      error: (%wrap-callback self error)})))


;; This function will return a 17 digit precision number of nanoseconds since Unix epoch.
;;
;; Args:
;;
;;     callback:   (optional)
;;                 A callback method should be passed to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;; Returns:
;;     Returns a 17 digit number in sync mode i.e. when callback
;;     argument is not given
;;
;;     Sample:
;;         13769501243685161
;;
(defmethod {time pubnub}
  (lambda (self callback: (callback #f))
    {%request ["time" "0"] #f callback: callback}))

(defmethod {get-url pubnub}
  (lambda (self url-components url-params encoder-map: (encoder-map #f))
    (when (and url-params (@ self u))
      (hash-put! url-params "u" (number->string (+ 1 (random-integer 100000000000)))))
    (when (and url-params (eqv? #f (hash-ref url-params "auth" #t)))
      (hash-remove! url-params "auth"))
    (def path
      (string-join (cons "" (map uri-encode url-components)) "/"))
    (def signature
      (and url-params
           (@ self secret-key)
           (let* ((_
                   (unless (hash-key? url-params "timestamp")
                     (hash-put! url-params "timestamp"
                                (time-second (current-time 'time-monotonic)))))
                  (url-second
                   (and (<= 3 (length url-components))
                        (list-ref url-components 2)))
                  (sign-third
                   (if (or (equal? url-second "grant") (equal? url-second "audit"))
                     url-second
                     path))
                  (params
                   (string-join
                    (map (lambda (key)
                           (string-append key "=" (uri-encode (hash-ref url-params key))))
                         (sort (hash-keys url-params) string<))
                    "&"))
                  (sign-input
                   (format "~a\n~a\n~a\n~a"
                           (@ self subscribe-key)
                           (@ self publish-key)
                           sign-third
                           params)))
             {%pam-sign self sign-input})))
    (def url
      (call-with-output-string
        []
        (lambda (port)
          (def (! x) (display x port))
          (! (@ self origin))
          (! path)
          (when url-params
            (let loop ((separator "?")
                       (keys (sort (hash-keys url-params) string<)))
              (unless (null? keys)
                (let* ((key (car keys))
                       (value (hash-ref url-params key)))
                  (when value
                    (! separator) (! key) (! "=")
                    (let ((encoder (or (and encoder-map (hash-get encoder-map key))
                                       uri-encode)))
                      (! (encoder (object->string value))))))
                (loop "&" (cdr keys))))
            (when signature
              (! "&signature=") (! signature))))))
    (when (@ self http-debug)
      ((@ self http-debug) url))
    url))

(defmethod {%channel-registry pubnub}
  (lambda (self url: (url #f) params: (params #f) callback: (callback #f) error: (error #f))
    (unless params
      (set! params (hash)))
    (def url-components
      `("v1" "channel-registration" "sub-key" (@ self subscribe-key)
        ,@(if url [url] '())))
    (hash-put! params "auth" (@ self auth-key))
    (hash-put! params "pnsdk" pubnub-sdk)
    (%request self url-components params
              callback: (%wrap-callback self callback) error: (%wrap-callback self error))))

(defmethod {%channel-group pubnub}
  (lambda (self
           channel-group: (channel-group #f)
           channels: (channels #f)
           cloak: (cloak #f)
           mode: (mode "add")
           callback: (callback #f)
           error: (error #f))
    (def params (hash))
    (def namespace #f)

    (when channel-group
      (let ((colon-index (string-index channel-group #\:)))
        (if colon-index
          (let ((ns (substring channel-group 0 colon-index)))
            (unless (equal? ns "*")
              (set! namespace ns))
            (set! channel-group
              (substring channel-group (+ 1 colon-index) (string-length channel-group)))))))

    (when channels
      (when (list? channels)
        (set! channels (string-join channels ",")))
      (hash-put! params mode channels)
      #; (hash-put! params "cloak" (if cloak "true" "false")))

    (def url
      `(,@(if namespace ["namespace" namespace] []) ;; NB: pubnub-python client gets that wrong!
        ,@(if (and channel-group (not (equal? channel-group "*")))
            ["channel-group" channel-group] []) ;; NB: pubnub-python always outputs "channel-group"
        ,@(if (and (not channels) (equal? mode "remove"))
            ["remove"] [])))

    {%channel-registry self url: url params: params callback: callback error: error}))

;; Get list of namespaces.
;;
;; You can obtain list of namespaces for the subscribe key associated with
;; PubNub object using this method.
;;
;; Args:
;;     callback:   (optional)
;;                 A callback method should be passed to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;;     error:      (optional)
;;                 Optional variable. An error method can be passed
;;                 to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;; Returns:
;;     Sync  Mode: dict
;;     channel-group-list-namespaces method returns a dict which
;;     contains list of namespaces in payload field
;;     {
;;         u'status': 200,
;;         u'payload': {
;;             u'sub-key': u'demo',
;;             u'namespaces': [u'dev', u'foo']
;;         },
;;         u'service': u'channel-registry',
;;         u'error': #f
;;     }
;;
;;     Async Mode: None (callback gets the response as parameter)
;;
;;     Response Format:
;;
;;     The callback passed to channel-group-list-namespaces gets the a
;;     dict containing list of namespaces under payload field
;;
;;     {
;;         u'payload': {
;;             u'sub-key': u'demo',
;;             u'namespaces': [u'dev', u'foo']
;;         }
;;     }
;;
;;     namespaces is the list of namespaces for the given subscribe key
;;
(defmethod {channel-group-list-namespaces pubnub}
  (lambda (self callback: (callback #f) error: (error #f))
    {%channel-registry self ["namespace"] callback: callback error: error}))

;; Remove a namespace.
;;
;; A namespace can be deleted using this method.
;;
;; Args:
;;     namespace:  (string) namespace to be deleted
;;     callback:   (optional)
;;                 A callback method should be passed to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;;     error:      (optional)
;;                 Optional variable. An error method can be passed to
;;                 the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;; Returns:
;;     Sync  Mode: dict
;;     channel-group-remove-namespace method returns a dict indicating
;;     status of the request
;;
;;     {
;;         u'status': 200,
;;         u'message': 'OK',
;;         u'service': u'channel-registry',
;;         u'error': #f
;;     }
;;
;;     Async Mode: None ( callback gets the response as parameter )
;;
;;     Response Format:
;;
;;     The callback passed to channel-group-list-namespaces gets the a
;;     dict indicating status of the request
;;
;;     {
;;         u'status': 200,
;;         u'message': 'OK',
;;         u'service': u'channel-registry',
;;         u'error': #f
;;     }
;;
(defmethod {channel-group-remove-namespace pubnub}
  (lambda (self namespace callback: (callback #f) error: (error #f))
    {%channel-registry self ["namespace" namespace "remove"] callback: callback error: error}))

;; Get list of groups.
;;
;; Using this method, list of groups for the subscribe key associated
;; with PubNub object, can be obtained. If namespace is provided, groups
;; within the namespace only are listed
;;
;; Args:
;;     namespace:  (string) (optional) namespace
;;     callback:   (optional)
;;                 A callback method should be passed to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;;     error:      (optional)
;;                 Optional variable. An error method can be passed to
;;                 the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;; Returns:
;;     Sync  Mode: dict
;;     channel-group-list-groups method returns a dict which contains
;;     list of groups in payload field
;;     {
;;         u'status': 200,
;;         u'payload': {"namespace": "dev", "groups": ["abcd"]},
;;         u'service': u'channel-registry',
;;         u'error': #f
;;     }
;;
;;     Async Mode: None ( callback gets the response as parameter )
;;
;;     Response Format:
;;
;;     The callback passed to channel-group-list-namespaces gets the a
;;     dict containing list of groups under payload field
;;
;;     {
;;         u'payload': {"namespace": "dev", "groups": ["abcd"]}
;;     }
(defmethod {channel-group-list-groups pubnub}
  (lambda (self namespace callback: (callback #f) error: (error #f))
    (let ((channel-group
           (if namespace (string-append namespace ":*") "*:*")))
      {%channel-group self channel-group: channel-group callback: callback error: error})))

;; Get list of channels for a group.
;;
;; Using this method, list of channels for a group, can be obtained.
;;
;; Args:
;;     channel-group: (string) (optional)
;;                 Channel Group name. It can also contain namespace.
;;                 If namespace is also specified, then the parameter
;;                 will be in format namespace:channel-group
;;
;;     callback:   (optional)
;;                 A callback method should be passed to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;;     error:      (optional)
;;                 Optional variable. An error method can be passed to the
;;                 method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;; Returns:
;;     Sync  Mode: dict
;;     channel-group-list-channels method returns a dict which contains
;;     list of channels in payload field
;;     {
;;         u'status': 200,
;;         u'payload': {"channels": ["hi"], "group": "abcd"},
;;         u'service': u'channel-registry',
;;         u'error': #f
;;     }
;;
;;     Async Mode: None ( callback gets the response as parameter )
;;
;;     Response Format:
;;
;;     The callback passed to channel-group-list-channels gets the a
;;     dict containing list of channels under payload field
;;
;;     {
;;         u'payload': {"channels": ["hi"], "group": "abcd"}
;;     }
;;
(defmethod {channel-group-list-channels pubnub}
  (lambda (self channel-group callback: (callback #f) error: (error #f))
    {%channel-group self channel-group: channel-group callback: callback error: error}))

;; Add a channel to group.
;;
;; A channel can be added to group using this method.
;;
;;
;; Args:
;;     channel-group:  (string)
;;                 Channel Group name. It can also contain namespace.
;;                 If namespace is also specified, then the parameter
;;                 will be in format namespace:channel-group
;;     channel:        (string)
;;                     Can be a channel name, a list of channel names,
;;                     or a comma separated list of channel names
;;     callback:       (optional)
;;                     A callback method should be passed to the method.
;;                     If set, the api works in async mode.
;;                     Required argument when working with twisted or
;;                     tornado.
;;
;;     error:      (optional)
;;                 Optional variable. An error method can be passed to
;;                 the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;; Returns:
;;     Sync  Mode: dict
;;     channel-group-add-channel method returns a dict indicating
;;     status of the request
;;
;;     {
;;         u'status': 200,
;;         u'message': 'OK',
;;         u'service': u'channel-registry',
;;         u'error': #f
;;     }
;;
;;     Async Mode: None ( callback gets the response as parameter )
;;
;;     Response Format:
;;
;;     The callback passed to channel-group-add-channel gets the a
;;     dict indicating status of the request
;;
;;     {
;;         u'status': 200,
;;         u'message': 'OK',
;;         u'service': u'channel-registry',
;;         u'error': #f
;;     }
;;
(defmethod {channel-group-add-channel pubnub}
  (lambda (self channel-group channel callback: (callback #f) error: (error #f))
    {%channel-group self channel-group: channel-group channel: channel mode: "add"
                    callback: callback error: error}))

;; Remove channel.
;;
;; A channel can be removed from a group method.
;;
;; Args:
;;     channel-group:  (string)
;;                 Channel Group name. It can also contain namespace.
;;                 If namespace is also specified, then the parameter
;;                 will be in format namespace:channel-group
;;     channel:        (string)
;;                     Can be a channel name, a list of channel names,
;;                     or a comma separated list of channel names
;;     callback:   (optional)
;;                 A callback method should be passed to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;;     error:      (optional)
;;                 Optional variable. An error method can be passed
;;                 to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;; Returns:
;;     Sync  Mode: dict
;;     channel-group-remove-channel method returns a dict indicating
;;     status of the request
;;
;;     {
;;         u'status': 200,
;;         u'message': 'OK',
;;         u'service': u'channel-registry',
;;         u'error': #f
;;     }
;;
;;     Async Mode: None ( callback gets the response as parameter )
;;
;;     Response Format:
;;
;;     The callback passed to channel-group-remove-channel gets the
;;     a dict indicating status of the request
;;
;;     {
;;         u'status': 200,
;;         u'message': 'OK',
;;         u'service': u'channel-registry',
;;         u'error': #f
;;     }
;;
(defmethod {channel-group-remove-channel pubnub}
  (lambda (self channel-group channel callback: (callback #f) error: (error #f))
    {%channel-group self channel-group: channel-group channel: channel mode: "remove"
                    callback: callback error: error}))

;; Remove channel group.
;;
;; A channel group can be removed using this method.
;;
;; Args:
;;     channel-group:  (string)
;;                 Channel Group name. It can also contain namespace.
;;                 If namespace is also specified, then the parameter
;;                 will be in format namespace:channel-group
;;     callback:   (optional)
;;                 A callback method should be passed to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;;     error:      (optional)
;;                 Optional variable. An error method can be passed
;;                 to the method.
;;                 If set, the api works in async mode.
;;                 Required argument when working with twisted or
;;                 tornado.
;;
;; Returns:
;;     Sync  Mode: dict
;;     channel-group-remove-group method returns a dict indicating
;;     status of the request
;;
;;     {
;;         u'status': 200,
;;         u'message': 'OK',
;;         u'service': u'channel-registry',
;;         u'error': #f
;;     }
;;
;;     Async Mode: None ( callback gets the response as parameter )
;;
;;     Response Format:
;;
;;     The callback passed to channel-group-remove-group gets the a
;;     dict indicating status of the request
;;
;;     {
;;         u'status': 200,
;;         u'message': 'OK',
;;         u'service': u'channel-registry',
;;         u'error': #f
;;     }
;;
(defmethod {channel-group-remove-group pubnub}
  (lambda (self channel-group callback: (callback #f) error: (error #f))
    {%channel-group self channel-group: channel-group mode: "remove"
                    callback: callback error: error}))

(defmethod {start pubnub}
  (lambda (self) (void)))

(defmethod {stop pubnub}
  (lambda (self) {%rest-offline self}))

(defmethod {nop pubnub}
  (lambda (self) (void)))


;; TODO: move this function to std/misc/list or some such.
;; This function helps built a list, by calling a building function that takes two arguments:
;; The first, which could be called poke (or put!, enqueue!, append-one-element-at-the-end!)
;; takes an element and puts it at the end of the list. The second, which could be called peek
;; (or get, get-list-so-far, get-shared-list-that-is-mutated-when-you-put), returns the
;; list of elements that poke has been called with, so far. When the building function returns,
;; call-with-list-builder will return the state of the list, as if by calling the peek function.
;; NB: this implementation accumulates elements by mutating a shared queue of cons cells;
;; in case of continuations, that same list is shared by all executions.
;; : (list X) <- (<- (<- X) ((list X) <-))
(def (call-with-list-builder fun)
  (let* ((head (cons #f '())) ;; use a traditional implementation of queue as cons of tail and head
         (poke (lambda (val)
                 (let ((old-tail (car head))
                       (new-tail (cons val '())))
                   (set-cdr! old-tail new-tail)
                   (set-car! head new-tail))))
         (peek (lambda () (cdr head))))
    (set-car! head head)
    (fun poke peek)
    (peek)))

(def (call-with-mutex mutex func)
  (if mutex (with-lock mutex func) (func)))
(defrules with-mutex ()
  ((_ mutex body ...) (call-with-mutex mutex (lambda () (body ...)))))

(def (%get-subscribed-foo-list foo-table nopresence mutex)
  (call-with-list-builder
   (lambda (found! _)
     (with-mutex mutex
       (let ((separator ""))
         (hash-for-each
          (lambda (foo-name foo-object)
            (unless (or (and nopresence (presence-name? foo-name))
                        (not (hash-get foo-object "subscribed")))
              (found! foo-name)))
          foo-table))))))

(def (list-as-string list)
  (and (not (null? list)) (string-join list ",")))

(defmethod {get-channel-list-as-string pubnub}
  (lambda (self nopresence: (nopresence #f))
    (list-as-string {get-channel-list self nopresence: nopresence})))

(defmethod {get-channel-group-list-as-string pubnub}
  (lambda (self nopresence: (nopresence #f))
    (list-as-string {get-channel-group-list self nopresence: nopresence})))

;; Get List of currently subscribed channels
;;
;; Returns:
;;     Returns a list containing names of channels subscribed
;;
;;     Sample return value:
;;         ["a","b","c]
;;
(defmethod {get-channel-list pubnub}
  (lambda (self nopresence: (nopresence #f))
    (%get-subscribed-foo-list
     (@ self subscriptions) nopresence (@ self channel-list-mutex))))

;; Get List of currently subscribed channel groups
;;
;; Returns:
;;     Returns a list containing names of channel groups subscribed
;;
;;     Sample return value:
;;         ["a","b","c]
;;
(defmethod {get-channel-group-list pubnub}
  (lambda (self nopresence: (nopresence #f))
    (%get-subscribed-foo-list
     (@ self subscription-groups) nopresence (@ self channel-group-list-mutex))))

(defmethod {restart-heartbeat pubnub}
  (lambda (self)
    {stop-heartbeat self}
    {restart-heartbeat self}))

(defmethod {stop-heartbeat pubnub}
  (lambda (self)
    {abort-heartbeat self}
    (set! (@ self heartbeat-running) #f)
    (set! (@ self heartbeat-stop-flag) #f)))

(defmethod {start-heartbeat pubnub}
  (lambda (self)
    (unless (@ self heartbeat-running)
      {%presence-heartbeat self})))

(def (%presence-heartbeat self)
  (when (or (not (@ self heartbeat-interval))
            (> (@ self heartbeat-interval) 500)
            (< (@ self heartbeat-interval) 1)
            (and (null? {get-channel-list self nopresence: #t})
                 (null? {get-channel-group-list self nopresence: #t})))
    (set! (@ self heartbeat-stop-flag) #t))
  (if (@ self heartbeat-stop-flag)
    (begin
      (set! (@ self heartbeat-running) #f)
      (set! (@ self heartbeat-stop-flag) #f))
    (begin
      (set! (@ self heartbeat-running) #t)
      {presence-heartbeat
       self
       callback: (lambda (resp)
                   (when (@ self heartbeat-callback)
                     ((@ self heartbeat-callback) resp))
                   (set! (@ self abort-heartbeat)
                     {timeout self (@ self heartbeat-interval) %presence-heartbeat}))
       error: (lambda (resp)
                (when (@ self heartbeat-error)
                  ((@ self heartbeat-error) resp))
                (set! (@ self abort-heartbeat)
                  {timeout self (@ self heartbeat-interval) %presence-heartbeat}))})))

(defmethod {set-heartbeat pubnub}
  (lambda (self heartbeat callback: (callback #f) error: (error #f))
    (set! (@ self heartbeat) heartbeat)
    (set! (@ self heartbeat-interval) (max 1 (- (/ heartbeat 2) 1)))
    {restart-heartbeat self}
    (with-mutex (@ self tt-mutex)
      (unless (zero? (@ self timetoken))
        (set! (@ self last-timetoken) (@ self timetoken)))
      {%connect self}
      (set! (@ self heartbeat-callback) callback)
      (set! (@ self heartbeat-error) error))))

(defmethod {get-heartbeat pubnub}
  (lambda (self) (@ self heartbeat)))

(defmethod {set-heartbeat-interval pubnub}
  (lambda (self heartbeat-interval)
    (set! (@ self heartbeat-interval) heartbeat-interval)
    {start-heartbeat self}))

(defmethod {get-heartbeat-interval pubnub}
  (lambda (self) (@ self heartbeat-interval)))

(defmethod {presence-heartbeat pubnub}
  (lambda (self callback: (callback #f) error: (error #f))
    (def data
      (hash
       ("auth" (@ self auth-key))
       ("pnsdk" pubnub-sdk)
       ("uuid" (@ self uuid))))
    (let ((st (json-object->string (@ self state))))
      (when (> (string-length st) 2)
        (hash-put! data "state" st)))
    (def channels (or {get-channel-list-as-string self nopresence: #t} ","))
    (def channel-groups {get-channel-group-list-as-string self nopresence: #t})
    (when channel-groups
      (hash-put! data "channel-group" channel-groups))
    (when (< 0 (@ self heartbeat) 320)
      (hash-put! data "heartbeat" (@ self heartbeat)))
    {%request
     self
     ["v2" "presence" "sub-key" (@ self subscribe-key) "channel" channels "heartbeat"]
     data
     callback: (%wrap-callback self callback)
     error: (%wrap-callback self error)}))

;; Subscribe to data on a channel.
;;
;; This function causes the client to create an open TCP socket to the
;; PubNub Real-Time Network and begin listening for messages on a
;; specified channel. To subscribe to a channel the client must send
;; the appropriate subscribe-key at initialization.
;;
;; Only works in async mode
;;
;; Args:
;;     channel:    (string/list)
;;                 Specifies the channel to subscribe to. It is possible
;;                 to specify multiple channels as a comma separated list
;;                 or array.
;;
;;     callback:   (function)
;;                 This callback is called on receiving a message from
;;                 the channel.
;;
;;     state:      (dict)
;;                 State to be set.
;;
;;     error:      (function) (optional)
;;                 This callback is called on an error event
;;
;;     connect:    (function) (optional)
;;                 This callback is called on a successful connection to
;;                 the PubNub cloud
;;
;;     disconnect: (function) (optional)
;;                 This callback is called on client disconnect from the
;;                 PubNub cloud
;;
;;     reconnect:  (function) (optional)
;;                 This callback is called on successfully re-connecting
;;                 to the PubNub cloud
;;
;; Returns:
;;     None
;;
(defmethod {subscribe pubnub}
  (lambda (self
           channels
           callback
           state: (state #f)
           error: (error #f)
           connect: (connect #f)
           disconnect: (disconnect #f)
           reconnect: (reconnect #f)
           presence: (presence #f)
           sync: (sync #f))
    {%subscribe
     self
     channels: channels
     callback: callback
     state: state
     error: error
     connect: connect
     disconnect: disconnect
     reconnect: reconnect
     presence: presence}))

;; Subscribe to data on a channel group.
;;
;; This function causes the client to create an open TCP socket to the
;; PubNub Real-Time Network and begin listening for messages on a
;; specified channel. To subscribe to a channel group the client must
;; send the appropriate subscribe-key at initialization.
;;
;; Only works in async mode
;;
;; Args:
;;     channel-groups:    (string/list)
;;                 Specifies the channel groups to subscribe to. It is
;;                 possible to specify multiple channel groups as a comma
;;                 separated list or array.
;;
;;     callback:   (function)
;;                 This callback is called on receiving a message from
;;                 the channel.
;;
;;     error:      (function) (optional)
;;                 This callback is called on an error event
;;
;;     connect:    (function) (optional)
;;                 This callback is called on a successful connection to
;;                 the PubNub cloud
;;
;;     disconnect: (function) (optional)
;;                 This callback is called on client disconnect from the
;;                 PubNub cloud
;;
;;     reconnect:  (function) (optional)
;;                 This callback is called on successfully re-connecting
;;                 to the PubNub cloud
;;
;; Returns:
;;     None
;;
(defmethod {subscribe-group pubnub}
  (lambda (self
           channel-groups
           callback
           error: (error #f)
           connect: (connect #f)
           disconnect: (disconnect #f)
           reconnect: (reconnect #f)
           presence: (presence #f)
           sync: (sync #f))
    {%subscribe
     self
     channel-groups: channel-groups
     callback: callback
     error: error
     connect: connect
     disconnect: disconnect
     reconnect: reconnect
     presence: presence}))

(def (hash-empty? h) (zero? (hash-length h)))

(defmethod {%subscribe pubnub}
  (lambda (self
           channels: (channels #f)
           channel-groups: (channel-groups #f)
           callback: (callback #f)
           state: (state #f)
           error: (error #f)
           connect: (connect #f)
           disconnect: (disconnect #f)
           reconnect: (reconnect #f)
           presence: (presence #f)
           sync: (sync #f))
    (with-mutex (@ self tt-mutex)
      (unless (zero? (@ self timetoken))
        (set! (@ self last-timetoken) (@ self timetoken))
        (set! (@ self timetoken) 0)))

    (def (%invoke func (msg #f) channel: (channel #f) real-channel: (real-channel #f))
      (when func
        (let ((user-msg (get-data-for-user msg)))
          (cond
           ((and msg channel real-channel)
            ;; TODO: make sure the function always takes two arguments
            (func msg channel real-channel))
           ((and msg channel)
            (func msg channel #f))
           (msg
            (func msg #f #f))
           (else (func))))))

    (def (%invoke-connect)
      (def (ensure-connection mutex table)
        (when mutex
          (with-mutex mutex
            (hash-for-each
             (lambda (_ obj)
               (cond
                ((not (hash-get obj "connected"))
                 (hash-put! obj "connected" #t)
                 (hash-put! obj "disconnected" #f)
                 (%invoke (hash-get obj "connect") (hash-get obj "name")))
                ((hash-get obj "disconnected")
                 (hash-put! obj "disconnected" #f)
                 (%invoke (hash-get obj "reconnect") (hash-get obj "name")))))
             table))))
      (ensure-connection (@ self channel-list-mutex) (@ self subscriptions))
      (ensure-connection (@ self channel-group-list-mutex) (@ self subscription-groups)))

    (def (%invoke-disconnect)
      (def (ensure-disconnection mutex table)
        (when mutex
          (with-mutex mutex
            (hash-for-each
             (lambda (_ obj)
               (when (and (hash-get obj "connected")
                          (not (hash-get obj "disconnected")))
                 (%invoke (hash-get obj "disconnect") (hash-get obj "name"))))
             table))))
      (ensure-disconnection (@ self channel-list-mutex) (@ self subscriptions))
      (ensure-disconnection (@ self channel-group-list-mutex) (@ self subscription-groups)))

    (def (%invoke-error channel-list: (channel-list #f) error: (error #f))
      (for-each
        (lambda (ch)
          (let ((obj (hash-get (@ self subscriptions) ch)))
            ;; TODO: make sure the error function takes two arguments. In python it's ugly.
            (%invoke (hash-get obj "error") error channel: ch)))
        (hash-keys (or channel-list (@ self subscriptions)))))

    (def (%get-channel)
      (find (lambda (obj) (hash-get obj "subscribed")) (hash-values (@ self subscriptions))))

    (def (%process-subscription-table keys table mutex update-state?)
      (when keys
        (let ((keys (cond ((list? keys) keys)
                          ((string? keys) (string-split keys #\,))))) ;; TODO: is "," valid here?
          (for-each
            (lambda (key)
              (when (or (not (hash-key? table key))
                        (not (hash-get (hash-get table key) "subscribed")))
                (with-mutex mutex
                  (hash-put!
                   table key
                   (hash
                    ("name" key)
                    ("first" #f)
                    ("connected" #f)
                    ("disconnected" #t)
                    ("subscribed" #t)
                    ("callback" callback)
                    ("connect" connect)
                    ("disconnect" disconnect)
                    ("reconnect" reconnect)
                    ("error" error)
                    ("presence" presence)))))
              (when update-state?
                (if state
                  (hash-put! state key
                             (if (hash-keys (@ self state) key)
                               (hash-get state key)
                               state)))))
            table))))
    (%process-subscription-table
     channels (@ self subscriptions) (@ self channel-list-mutex) #t)
    (%process-subscription-table
     channels (@ self subscription-groups) (@ self channel-group-list-mutex) #f)

    {restart-heartbeat self}

    ;; SUBSCRIPTION RECURSION
    (def (%connect)

      {%reset-offline self}

      (def (error-callback response)
        (cond
         ;; python code also accept weird condition of empty response here
         ((equal? (hash-get response "message") "Forbidden")
          (%invoke-error
           channel-list: (hash-get (hash-get response "payload") "channels")
           error: (hash-get response "message"))
          {timeout self 1 %connect})
         ((hash-get response "message") => (lambda (msg) (%invoke-error error: msg)))
         (else
          (%invoke-disconnect)
          (set! (@ self timetoken) 0)
          {timeout self 1 %connect})))

      (def (sub-callback response)
        ;; python code also had a non-sensical snippet, seemingly copied from the previous function,
        ;; that assumed response was a dict, when the rest of the function assumes it's a list.
        (%invoke-connect)
        (with-mutex (@ self tt-mutex)
          (set! (@ self timetoken)
            (if (and (zero? (@ self timetoken))
                     (not (zero? (@ self last-timetoken))))
              (@ self last-timetoken)
              (list-ref response 1)))
          (cond
           ((< 3 (length response))
            (let ((channel-list (string-split (list-ref response 2) #\,))
                  (channel-list-2 (string-split (list-ref response 3) #\,))
                  (response-list (list-ref response 0)))
              (for-each
                (match <>
                  ([channel channel-2 response]
                   (cond
                    ((or (hash-get (@ self subscription-groups) channel)
                         (hash-get (@ self subscriptions) channel))
                     => (lambda (obj)
                          (let-values (((callback name name-2)
                                        (if (presence-name? channel-2)
                                          (values (hash-get obj "presence")
                                                  (unpresence-name (hash-get obj "name"))
                                                  (unpresence-name channel-2))
                                          (values (hash-get obj "callback")
                                                  (hash-get obj "name")
                                                  channel-2))))
                            (%invoke callback {decrypt self response}
                                     channel: name real-channel: name-2)))))))
                (zip channel-list channel-list-2 response-list))))
           ((= 3 (length response))
            (let ((channel-list (string-split (list-ref response 2) #\,))
                  (response-list (list-ref response 0)))
              (for-each
                (match <>
                  ([channel response]
                   (let ((obj (hash-get (@ self subscriptions) channel)))
                     ;; Why does this case not use a separate callback for pnpres as above?
                     (%invoke callback {decrypt self response} channel: channel))))
                (zip channel-list response-list))))
           (else
            (let ((response-list (list-ref response 0))
                  (obj (%get-channel)))
              (when obj
                (for-each
                  (lambda (r)
                    (%invoke callback {decrypt self r}
                             channel: (unpresence-name (hash-get obj "name"))))
                  response-list)))))
          (%connect)))

      (def channel-list {get-channel-list-as-string self (@ self subscriptions)})
      (def channel-group-list {get-channel-group-list-as-string self (@ self subscription-groups)})

      (when (or (< 0 (string-length channel-list))
                (< 0 (string-length channel-group-list)))
        (unless channel-list (set! channel-list ","))
        (let ((data
               (hash ("uuid" (@ self uuid))
                     ("auth" (@ self auth-key))
                     ("pnsdk" pubnub-sdk)))
              (st (json-object->string (@ self state))))
          (when channel-group-list
            (hash-put! data "channel-group" channel-group-list))
          (when (< 2 (string-length st))
            (hash-put! data "state" st)) ;; ???? python uses a redundant uri-encode, here
          (when (< 0 (@ self heartbeat))
            (hash-put! data "heartbeat" (@ self heartbeat)))

          ;; CONNECT TO PUBNUB SUBSCRIBE SERVERS
          ;;(try
          (set! (@ self sub-receiver)
            {%request
             self
             ["subscribe" (@ self subscribe-key)
              channel-list "0" (object->string (@ self timetoken))]
             data
             callback: sub-callback
             error: error-callback
             single: #t
             timeout: 320}))))

    (set! (@ self connect) %connect)

    ;; BEGIN SUBSCRIPTION (LISTEN FOR MESSAGES)
    (%connect)))

(defmethod {%reset-offline pubnub}
  (lambda (self)
    (when (@ self sub-receiver)
      (@ self sub-receiver)
      (set! (@ self sub-receiver) #f))))

(defmethod {connect pubnub}
  (lambda (self)
    {%reset-offline self}
    {%connect self}))

;; foo can be a channel or a channel-group
(def (%unsubscribe-foo self foo table mutex leave update-state)
  (when (hash-key? table foo)
    ;; DISCONNECT
    (with-mutex mutex
      (let ((obj (hash-get table foo)))
        (when obj
          (hash-put! obj "connected" 0)
          (hash-put! obj "subscribed" #f)
          (hash-put! obj "timetable" 0)
          (hash-put! obj "first" #f)
          (leave)))
      ;; remove channel from state
      (update-state))
    {%connect self}))

;; Unsubscribe from channel.
;;    Only works in async mode
;;
;; Args:
;;     channel: Channel name ( string )
;;
(defmethod {unsubscribe pubnub}
  (lambda (self channel)
    (%unsubscribe-foo
     self channel
     (@ self subscriptions) (@ self channel-list-mutex)
     (lambda () {leave-channel self channel})
     (lambda () (hash-remove! (@ self state) channel)))))


;; Unsubscribe from channel group.
;;    Only works in async mode
;;
;; Args:
;;     channel-group: Channel group name ( string )
;;
(defmethod {unsubscribe-group pubnub}
  (lambda (self channel-group)
    (%unsubscribe-foo
     self channel-group
     (@ self subscription-groups) (@ self channel-group-list-mutex)
     (lambda () {leave-group self channel-group})
     void)))

(defclass timer
  (timeout func stop thread))

(defmethod {init! timer}
  (lambda (self
           timeout
           func)
    (set! (@ self timeout) timeout)
    (set! (@ self func) func)
    (set! (@ self stop) #f)
    (set! (@ self thread) #f)))

(defmethod {cancel timer}
  (lambda (self)
    (set! (@ self stop) #t)
    (set! (@ self func) #f)))

(defmethod {run timer}
  (lambda (self)
    (thread-sleep! (@ self timeout))
    (when (@ self func)
      (apply (@ self func) (@ self arguments)))))

(defmethod {start timer}
  (lambda (self)
    (set! (@ self thread) (spawn (lambda () {run self})))))

(defclass http-client
  (pubnub
   url
   id
   callback
   error
   stop
   timeout)
  constructor: init!)

(defmethod {init! http-client}
  (lambda (self
           pubnub url
           callback: (callback #f) error: (error #f) id: (id #f) timeout: (timeout 15))
    (set! (@ self pubnub) pubnub)
    (set! (@ self url) url)
    (set! (@ self id) id)
    (set! (@ self callback) callback)
    (set! (@ self error) error)
    (set! (@ self timeout) timeout)
    (set! (@ self stop) #f)))

(defmethod {cancel http-client}
  (lambda (self)
    (set! (@ self stop) #t)
    (set! (@ self callback) #f)
    (set! (@ self error) #f)))

(defmethod {run http-client}
  (lambda (self)
    (def (%invoke func data)
      (when func
        (func (get-data-for-user data))))
    (def (%handle-response code data callback error)
      (let/cc k
        (try
         (set! data (string->json-object data))
         (catch (_) (k (%invoke error (hash ("error" "json decoding error"))))))
        (if (= code 200)
          (%invoke callback data)
          (%invoke error data))))
    (let ((resp (get-http-response (@ self url) timeout: (@ self timeout))))
      (unless (@ self stop)
        (match resp
          ([data code]
           (if (not (@ self callback))
             (with-mutex (@ self pubnub latest-sub-callback-mutex)
               (when (and (equal? (@ self id) (hash-get (@ self pubnub latest-sub-callback) "id"))
                          (hash-get (@ self pubnub latest-sub-callback) "callback"))
                 (hash-put! (@ self pubnub latest-sub-callback) "id" 0)
                 (%handle-response code data
                               (hash-get (@ self pubnub latest-sub-callback) "callback")
                               (hash-get (@ self pubnub latest-sub-callback) "error"))))
             (%handle-response code data (@ self callback) (@ self error)))))))))


;; The python returns a pair (content, code)
;; TODO: handle timeout
(def (get-http-response url timeout: (timeout 15))
  (let (req (http-get url))
    (try
     [(request-status req) (request-content req)] ;; also (request-status-text req)
     (catch (e) [0 (object->string e)])
     (finally
      (request-close req)))))

;; TODO: handle timeouts? And/or have a library for handling timeouts in general.
(def (%request self url)
  ;; Send Request Expecting JSON Response
  (let ((req (http-get url)))
    (try
     (let ((status (request-status req)))
       (unless (equal? status 200)
         (error "Request failed" status (request-status-text status)))
       (json-object->string (request-content req)))
     (finally
      (request-close req)))))

(defmethod {%request pubnub}
  (lambda (self
           url-components
           url-params
           callback: (callback #f)
           error: (error #f)
           single: (single #f)
           timeout: (timeout 15)
           encoder-map: (encoder-map #f))
    (let ((url {get-url self url-components url-params encoder-map}))
      (get-data-for-user
       {%request url timeout: timeout}))))
