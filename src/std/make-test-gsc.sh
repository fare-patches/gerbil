#!/bin/sh
# gsc fixture for make-test.ss. A ready file is a barrier, never a delay
# guessed from how long a native compilation usually takes.
set -eu
for arg do input=$arg; done
cd "$MAKE_TEST_CONTROL"
wait_for() {
    n=0
    until test -f "$1"; do
        n=$((n+1))
        test "$n" -le 600 || { echo "barrier timed out: $1" >&2; exit 125; }
        sleep 0.1
    done
}
case "$MAKE_TEST_MODE:${input##*/}" in
    race:*a~0.scm|race:*a.scm)
        # Capture the logical object selected by the driver before gsc runs.
        # An unstaged driver supplies no linker name; still reach the barrier.
        prev= name=implicit
        for arg do
            if test "$prev" = -linker-name; then name=$arg; fi
            prev=$arg
        done
        case "${input##*/}" in
            *a~0.scm) printf '%s\n' "$name" >section ;;
            *) printf '%s\n' "$name" >loader
               printf '%s\n' "$input" >loader-input
               touch ready
               wait_for release ;;
        esac ;;
    trace:*a~0.scm)
        printf '%s\n' "$input" >input ;;
    link-failure:*a~0.scm)
        printf '%s\n' "$input" >input
        touch ready
        wait_for release
        exec "$MAKE_TEST_GSC" -ld-options "-lmissing_gerbil_make_test_library" "$@" ;;
    siblings:*a~inner~0.scm)
        touch ready
        wait_for failing-pid
        pid=$(cat failing-pid)
        n=0
        while kill -0 "$pid" 2>/dev/null; do
            n=$((n+1))
            test "$n" -le 600 || exit 125
            sleep 0.1
        done
        touch failed
        wait_for release
        "$MAKE_TEST_GSC" "$@"
        touch late-success
        exit 0 ;;
    siblings:*a~0.scm)
        wait_for ready
        echo "$$" >pid.tmp
        mv pid.tmp failing-pid
        exit 41 ;;
    obstruct:*a.scm)
        "$MAKE_TEST_GSC" "$@"
        mv "$MAKE_TEST_SECTION" prior.scm
        mkdir "$MAKE_TEST_SECTION"
        touch "$MAKE_TEST_SECTION/block-rename" obstructed
        exit 0 ;;
esac
exec "$MAKE_TEST_GSC" "$@"
