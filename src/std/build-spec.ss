;; -*- Gerbil -*-
;; (C) Gerbil contributors
;; gerbil stdlib build spec
(def (gerbil-libdir) (path-expand "lib" (getenv "GERBIL_BUILD_PREFIX" (gerbil-home))))

(def (build-spec . _)
  `(;; v0.19 stdlib
    (gxc: "build-config" (extra-inputs: ("build-features.ss")))
    "interactive"
    "error"
    "interface"
    "instance"
    "deprecation"

    "debug/DBG"

    "list/list-builder"
    "list/list"
    "list/alist"
    "list/plist"
    "list/walist"
    "list/random"

    "iter/interface"
    "iter/iterators"
    "iter/macros"
    "iter/api"
    "iter"

    "string/misc"
    "string/path"
    "string/utf8"
    "string/stringer"
    "string/uuid"
    "string/symbol"

    "cache"
    "sync/rwlock"
    "sync/spinlock"
    "sync/threads"

    "net/address/types"
    "net/address/parser"
    "net/address/stringer"
    "net/address/resolver"
    "net/address/serde"
    "net/address/api"
    "net/address"

    "ffi"
    "os/error"
    (gxc: "os/device" ,@(include-gambit-sharp))
    (gxc: "os/file" "-cc-options" "-D_LARGEFILE64_SOURCE")
    "os/fcntl"
    "os/flock"
    (gxc: "os/pipe" "-cc-options" "-D _GNU_SOURCE")
    ,@(cond-expand
        (linux '("os/inotify"))
        (else '()))
    "os/time"
    "os/sockaddr"
    (gxc: "os/socket" "-cc-options" "-D _GNU_SOURCE")
    "os/sockopt"
    "os/hostname"
    "os/pid"
    "os/signal"
    (gxc: "os/signal-test-support" (extra-inputs: ("os/signal.ss")))
    ,@(cond-expand
        (linux '("os/signalfd"))
        (bsd '("os/kqueue"))
        (else '()))
    "os/signal-handler"

    "io/interface/base"
    "io/interface/bio"
    "io/interface/socket"
    "io/interface"
    "io/bio/types"
    "io/bio/buffer"
    "io/bio/macros"
    "io/bio/cache"
    "io/bio/input"
    "io/bio/output"
    "io/bio/reader"
    "io/bio/writer"
    "io/bio/delimited"
    "io/bio/memory"
    "io/bio/srcsnk"
    "io/bio/port"
    "io/bio/api"
    "io/file"
    "io/tempfile"
    "io/util"
    "io/counter"
    "io/delimited"
    "io/detachable"
    "io/dummy"
    "io/socket/types"
    "io/socket/sockaddr"
    "io/socket/socket"
    "io/socket/basic"
    "io/socket/client"
    "io/socket/stream"
    "io/socket/server"
    "io/socket/datagram"
    "io/socket/api"
    "io/api"
    "io"

    "serde/interface"
    "serde/util"
    "serde/scan"
    "serde/scanner"
    "serde/serialize"
    "serde/deserialize"
    "serde/interned"
    "serde/binary"
    "serde/marshal"
    (gxc: "serde/unmarshal" ,@(include-gambit-sharp))
    "serde/serde-test-support"

    "format/ascii"
    "format/format-string"
    "format/env"
    "format/ioutil"
    "format/writer"
    (gxc: "format/reader" ,@(include-gambit-sharp))
    "format/io"
    "format/format"
    "format/api"
    "format"

    "assert"

    "time/time"
    "time/timeout"
    "time/precise"
    (gxc: "time/date" "-cc-options" "-D _GNU_SOURCE")

    "sync/atom"
    "sync/channel"
    "sync/completion"
    "sync/barrier"
    "sync/wg"

    "make"
    "build-script"

    "test/base"
    "test/unit"
    "test"

    "values"
    "func"
    "shuffle"
    "stxparam"

    "hash/types"
    "hash/misc"

    "struct/deque"
    "struct/lru"
    "struct/option"
    "struct/queue"
    "struct/pqueue"
    "struct/rbtree"
    "struct/dag"

    "cli/getopt"
    "cli/multicall"
    "cli/print-exit"
    "cli/shell"

    "text/pregexp"
    "text/glob"
    "text/parser/char-set"
    "text/parser/base"
    "text/parser/ll1"
    "text/template"
    "text/include"

    (gxc: "text/parser/ebnf/stream" ,@(include-gambit-sharp))
    "text/parser/ebnf/rlang"
    "text/parser/ebnf/lexer"
    "text/parser/ebnf/defparser"
    "text/parser/ebnf/rx-parser"
    "text/parser/ebnf/deflexer"
    "text/parser/ebnf/lang-reader"
    "text/parser/ebnf/lang"
    "text/parser/ebnf"

    "encoding/protobuf/io"
    "encoding/protobuf/macros"
    "encoding/protobuf/grammar"
    "encoding/protobuf/lang"

    (gxc: "crypto/libcrypto"
          "-cc-options" ,(append-options (cppflags "libcrypto" "") "-Wno-discarded-qualifiers" "-Wno-deprecated-declarations" "-Wno-implicit-function-declaration")
          "-ld-options" ,(ldflags "libcrypto" "-lcrypto"))
    "crypto/error"
    "crypto/random"
    "crypto/digest"
    "crypto/cipher"
    "crypto/pkey"
    "crypto/kdf"
    "crypto/hmac"

    ,(cond-expand
      (darwin
       `(gxc: "net/ssl/libssl"
	      "-cc-options" ,(append-options (cppflags "libssl" "") "-Wno-discarded-qualifiers")
	      "-ld-options" ,(apply append-options
			               (ldflags "libssl" "-lssl")
			               (ldflags "libcrypto" "-lcrypto")
                           (if (enable-shared?)
                             [(string-append "-L" (gerbil-libdir)) "-lgambit"]
                             []))))
      (else
       `(gxc: "net/ssl/libssl"
	      "-ld-options" ,(ldflags "libssl" "-lssl"))))
    "net/ssl/error"
    (gxc: "net/ssl/error-test-support"
          "-cc-options" ,(cppflags "libssl" "")
          "-ld-options" ,(ldflags "libcrypto" "-lcrypto"))
    "net/ssl/interface"
    "net/ssl/socket"
    "net/ssl/client"
    "net/ssl/server"
    "net/ssl/api"
    "net/ssl"

    "net/smtp/interface"
    "net/smtp/data"
    "net/smtp/session"
    "net/smtp/client"
    "net/smtp/connection"
    "net/smtp/headers"
    "net/smtp/api"
    "net/smtp"

    "net/socks/interface"
    "net/socks/client"
    "net/socks/server"
    "net/socks/api"
    "net/socks"

    "encoding/base64"
    "encoding/base32"
    "encoding/base58"
    "encoding/hex"
    "encoding/json/env"
    "encoding/json/writer"
    "encoding/json/reader"
    "encoding/json/io"
    "encoding/json/util"
    "encoding/json/api"
    "encoding/json"
    "encoding/csv"

    "vector/u8vector"

    "encoding/utf16"
    "encoding/utf32"
    "encoding/utf8"

    "vector/extensible"
    "vector/vector"

    "number/misc"
    "number/prime"
    "number/decimal"
    "number/writer"

    "misc/process"
    "misc/ports"

    "source"

    ,@(if config-enable-zlib
        `((gxc: "encoding/zlib"
                "-cc-options" ,(cppflags "zlib" "")
                "-ld-options" ,(ldflags "zlib" "-lz")))
        '())

    "net/uri"
    "net/url"
    "net/http/common/ioutil"
    "net/http/common/chunked"
    "net/http/client/request"
    "net/http/client/methods"
    "net/http/client/util"
    "net/http/client/api"
    "net/http/client"
    "net/request"

    "log/interface"
    "log/level"
    "log/proto"
    "log/macros"
    "log/console"
    "log/system"
    "log/user"
    "log/format"
    "log/default"
    "log/rotate"
    "log/compress"
    "log/api"
    "log"

    (gxc: "net/repl" ,@(include-gambit-sharp))

    "net/mime/struct"
    "net/mime/types"
    "net/mime/file"

    "net/http/server/interface"
    "net/http/server/status"
    "net/http/server/handlers/empty"
    "net/http/server/handlers/file"
    "net/http/server/handlers/directory"
    "net/http/server/handlers/closure"
    "net/http/server/mux/static"
    "net/http/server/request"
    "net/http/server/server"
    "net/http/server/api"
    "net/http/server"

    "net/websocket/interface"
    "net/websocket/socket"
    "net/websocket/client"
    "net/websocket/server"
    "net/websocket/api"
    "net/websocket"

    "net/json-rpc"
    "net/sasl"

    "db/interface"
    "db/db"
    "db/cache"
    "db/schema"
    "db/connpool"
    "db/query"
    "db/postgresql-driver"
    "db/postgresql"

    "actor/message"
    "actor/host"
    "actor/state"
    (gxc: "actor/interaction" ,@(include-gambit-sharp))
    "actor/proto"
    "actor/serde"
    "actor/api"
    "actor"

    "ensemble/ucan/interface"
    "ensemble/ucan/did"
    "ensemble/ucan/util"
    "ensemble/ucan/cap"
    "ensemble/ucan/ext"

    "ensemble/network/config"
    "ensemble/network/log"
    "ensemble/network/thread"
    "ensemble/network/listener"
    "ensemble/network/wire"
    "ensemble/network/auth"
    "ensemble/network/handshake"
    "ensemble/network/connector"
    "ensemble/network/network"
    "ensemble/network/stream"
    "ensemble/network/connection"
    "ensemble/network/renewal"
    "ensemble/network/interface"
    "ensemble/network/tls"
    "ensemble/network"

    "ensemble/keystore/interface"
    "ensemble/keystore/crypto"
    "ensemble/keystore/store"
    "ensemble/keystore/memory"
    "ensemble/keystore/persistent"
    "ensemble/keystore/api"
    "ensemble/keystore"

    ,@(if config-enable-sqlite
        `((gxc: "db/sqlite-driver"
                "-cc-options" ,(cppflags "sqlite3" "")
                "-ld-options" ,(append-options (ldflags "sqlite3" "-lsqlite3") "-lm"))
          "db/sqlite"
          (gxc: "ensemble/ucan/db" (extra-inputs: ("ensemble/ucan/db.sql")))
          "ensemble/ucan/context")
        '())
    "db"

    "encoding/multibase"

    "text/markup/sxml/print"
    (gxc: "text/markup/sxml/ssax")
    "text/markup/sxml/sxpath"
    "text/markup/sxml/xml"
    "text/markup/sxml/sxml-inf"
    (gxc: "text/markup/sxml/html/parser" (extra-inputs: ("text/markup/sxml/html/html-parser.scm")))
    "text/markup/sxml"
    "text/markup/scan-input"
    "text/markup/input"
    "text/markup/output"
    "text/markup/sink"
    "text/markup/xml/node"
    "text/markup/xml/scanner"
    "text/markup/xml/types"
    "text/markup/xml/reader"
    "text/markup/xml/emitter"
    "text/markup/xml/writer"
    "text/markup/xml"
    "text/markup/html/node"
    "text/markup/html/atoms"
    "text/markup/html/rules"
    "text/markup/html/types"
    "text/markup/html/entities"
    "text/markup/html/scanner"
    "text/markup/html/tokenizer"
    "text/markup/html/builder"
    "text/markup/html/reader"
    "text/markup/html/emitter"
    "text/markup/html/writer"
    "text/markup/html"
    "text/markup/djot/ast"
    "text/markup/djot/attributes"
    "text/markup/djot/inline"
    "text/markup/djot/block"
    "text/markup/djot/parse"
    "text/markup/djot/html"
    "text/markup/djot/api"
    "text/markup/djot"

    "net/s3/interface"
    "net/s3/sigv4"
    "net/s3/response"
    "net/s3/client"
    "net/s3"

    "text/markup/tal/reader"
    "text/markup/tal/compiler"
    "text/markup/tal/runtime"
    "text/markup/tal"
    ))
