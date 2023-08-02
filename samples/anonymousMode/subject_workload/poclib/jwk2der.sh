#!/bin/bash
set -e

# FUNCTIONS
decodeBase64UrlUInt() { #input:base64UrlUnsignedInteger
    local binaryDigits paddedStr
    case $(( ${#1} % 4 )) in
        2) paddedStr="$1=="   ;;
        3) paddedStr="$1="    ;;
        *) paddedStr="$1"     ;;
    esac
    binaryDigits=$(             \
        echo -n "$paddedStr"    \
        | tr '_-' '/+'          \
        | openssl enc -d -a -A  \
        | xxd -b -g 0           \
        | cut -d ' ' -f 2       \
        | paste -s -d ''        \
    )
    echo "ibase=2; obase=A; $binaryDigits" | bc
    # openssl   enc:encoding; -d=decrypt; -a=-base64; -A=singleLineBuffer
    # xxd       "make-hexdump": -b=bits; -g=groupsize
    # cut       -d=delimiter; -f=field
    # paste     -s=serial|singleFile; -d=delimiter
}

base64UrlToHex() { #input:base64UrlString
    local hexStr paddedStr
    case $(( ${#1} % 4 )) in
        2) paddedStr="$1=="   ;;
        3) paddedStr="$1="    ;;
        *) paddedStr="$1"     ;;
    esac
    hexStr=$(                   \
        echo -n "$paddedStr"    \
        | tr '_-' '/+'          \
        | base64 -d             \
        | xxd -p -u             \
        | tr -d '\n'            \
    )
    echo "$hexStr"
    # base64    -d=decode
    # xxd       -p=-plain=continuousHexDump; -u=upperCase
    # tr        -d=delete
}

asn1Conf() { #input:hexStrPlainUpperCase
    local e="$1"
    local n="$2"
    echo "
        asn1 = SEQUENCE:pubkeyinfo
        [pubkeyinfo]
        algorithm = SEQUENCE:rsa_alg
        pubkey = BITWRAP,SEQUENCE:rsapubkey
        [rsa_alg]
        algorithm = OID:rsaEncryption
        parameter = NULL
        [rsapubkey]
        n = INTEGER:0x$n
        e = INTEGER:0x$e
    " | sed '/^$/d ; s/^ *//g'              \
    | openssl asn1parse                     \
        -genconf    /dev/stdin              \
        -out        /dev/stdout             \
    | openssl rsa                           \
        -pubin                              \
            -inform     DER                 \
            -outform    PEM                 \
            -in         /dev/stdin          \
            -out        ./keys/oauth.pem
    # sed       /^$/d=removeEmptyLines; /^ */=removeLeadingSpaces
}

main() {
    local e n hexArr
    local jwksUrl="$1"
    local jwkJson=$(curl -sSSL $jwksUrl)
    local kidList=$(jq -r '.keys[].kid' <<< "$jwkJson")
    for keyId in $kidList; do
        n=$(jq -r ".keys[] | select(.kid == \"$keyId\") | .n" <<< "$jwkJson")
        e=$(jq -r ".keys[] | select(.kid == \"$keyId\") | .e" <<< "$jwkJson")
        echo -e "\n$keyId"
        # decodeBase64UrlUInt "$e"
        # decodeBase64UrlUInt "$n"
        asn1Conf $(base64UrlToHex "$e") $(base64UrlToHex "$n")
    done
}

# MAIN
main ''$1''
exit 0