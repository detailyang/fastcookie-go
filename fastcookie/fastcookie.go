package fastcookie

import (
	"bytes"
	"strconv"
	"time"
)

// CookiePair holds the name & value
type CookiePair struct {
	name  []byte
	value []byte
}

func (q *CookiePair) set(name, value []byte) {
	q.name = append(q.name[:0], name...)
	q.value = append(q.value[:0], value...)
}

func (q *CookiePair) reset() {
	q.name = q.name[:0]
	q.value = q.value[:0]
}

type FastCookie struct {
	pairs       []CookiePair
	tmpkv       []byte
	tmpv        []byte
	expires     time.Time
	rawExpires  []byte
	maxAge      int
	rawMaxAge   []byte
	domain      []byte
	path        []byte
	httpOnly    bool
	rawHTTPOnly []byte
	secure      bool
	rawSecure   []byte
	samesite    []byte
}

func (fc *FastCookie) Parse(c [][]byte) {
	ParseCookie(fc, c)
}

func (fc *FastCookie) GetExpires() time.Time {
	return fc.expires
}

func (fc *FastCookie) GetRawExpires() []byte {
	return fc.rawExpires
}

func (fc *FastCookie) GetMaxAge() int {
	return fc.maxAge
}

func (fc *FastCookie) GetRawMaxAge() []byte {
	return fc.rawMaxAge
}

func (fc *FastCookie) GetDomain() []byte {
	return fc.domain
}

func (fc *FastCookie) GetPath() []byte {
	return fc.path
}

func (fc *FastCookie) GetHTTPOnly() bool {
	return fc.httpOnly
}

func (fc *FastCookie) GetRawHTTPOnly() []byte {
	return fc.rawHTTPOnly
}

func (fc *FastCookie) GetSecure() bool {
	return fc.secure
}

func (fc *FastCookie) GetRawSecure() []byte {
	return fc.rawSecure
}

func (fc *FastCookie) GetSameSite() []byte {
	return fc.samesite
}

func (fc *FastCookie) Reset() {
	for i := range fc.pairs {
		fc.pairs[i].reset()
	}
	fc.pairs = fc.pairs[:0]
	fc.tmpkv = fc.tmpkv[:0]
	fc.tmpv = fc.tmpv[:0]
	fc.expires = time.Time{}
	fc.rawExpires = fc.rawExpires[:0]
	fc.maxAge = 0
	fc.rawMaxAge = fc.rawMaxAge[:0]
	fc.domain = fc.domain[:0]
	fc.path = fc.path[:0]
	fc.httpOnly = false
	fc.rawHTTPOnly = fc.rawHTTPOnly[:0]
	fc.secure = false
	fc.rawSecure = fc.rawSecure[:0]
	fc.samesite = fc.samesite[:0]
}

func (f *FastCookie) alloc() *CookiePair {
	n := len(f.pairs)
	c := cap(f.pairs)
	if n == c {
		f.pairs = append(f.pairs, make([]CookiePair, 4)...)
	}
	f.pairs = f.pairs[:n+1]
	return &f.pairs[n]
}

func (f *FastCookie) removeLastPair() {
	if n := len(f.pairs); n >= 1 {
		f.pairs = f.pairs[:n-1]
	}
}

// ParseCookie parses multi cookie to FastCookie
// The Cookie header field [COOKIE] uses a semi-colon (";") to delimit
// cookie-pairs (or "crumbs").  This header field doesn't follow the
// list construction rules in HTTP (see [RFC7230], Section 3.2.2), which
// prevents cookie-pairs from being separated into different name-value
// pairs.  This can significantly reduce compression efficiency as
// individual cookie-pairs are updated.
//
// To allow for better compression efficiency, the Cookie header field
// MAY be split into separate header fields, each with one or more
// cookie-pairs.  If there are multiple Cookie header fields after
// decompression, these MUST be concatenated into a single octet string
// using the two-octet delimiter of 0x3B, 0x20 (the ASCII string "; ")
// before being passed into a non-HTTP/2 context, such as an HTTP/1.1
// connection, or a generic HTTP server application.
//
// Therefore, the following two lists of Cookie header fields are
// semantically equivalent.
//
//   cookie: a=b; c=d; e=f
//
//   cookie: a=b
//   cookie: c=d
//   cookie: e=f
func ParseCookie(c *FastCookie, cookies [][]byte) {
	var (
		ck []byte
		cv []byte
	)
	for i := range cookies {
		cookie := cookies[i]
		var part []byte
		for len(cookie) > 0 {
			ci := bytes.IndexByte(cookie, ';')
			if ci > 0 {
				part, cookie = cookie[:ci], cookie[ci+1:]
			} else {
				part, cookie = cookie, nil
			}

			if len(part) == 0 {
				continue
			}

			var value []byte
			if ci := bytes.IndexByte(part, '='); ci >= 0 {
				part, value = part[:ci], part[ci+1:]
			}

			ck = decodeCookieArg(ck[:0], part, false)
			cv = decodeCookieArg(cv[:0], value, true)
			c.Set(ck, cv)
		}
	}
}

func (fc *FastCookie) Get(name []byte) ([]byte, bool) {
	for i := range fc.pairs {
		if bytes.Equal(fc.pairs[i].name, name) {
			return fc.pairs[i].value, true
		}
	}
	return nil, false
}

func (fc *FastCookie) Set(name, value []byte) {
	fc.tmpkv = append(fc.tmpkv[:0], name...)
	toLowercsaeASCII(fc.tmpkv)
	switch len(fc.tmpkv) {
	case 4:
		fc.set4(name[:4], fc.tmpkv[:4], value)
	case 6:
		fc.set6(name[:6], fc.tmpkv[:6], value)
	case 7:
		fc.set7(name[:7], fc.tmpkv[:7], value)
	case 8:
		fc.set8(name[:8], fc.tmpkv[:8], value)
	default:
		fc.set(name, fc.tmpkv, value)
	}
}

func (fc *FastCookie) set(name, lowcaename, value []byte) {
	pair := fc.alloc()
	pair.set(name, value)
}

func (fc *FastCookie) set4(name, lowcaename []byte, value []byte) {
	_ = name[:4]
	_ = lowcaename[:4]
	switch string(lowcaename[:4]) {
	case "path":
		fc.path = append(fc.path[:0], value...)
		return
	}
	fc.set(name, lowcaename, value)
}

func (fc *FastCookie) set6(name, lowcaename []byte, value []byte) {
	_ = name[:6]
	_ = lowcaename[:6]
	switch string(lowcaename[:4]) {
	case "secu":
		if string(lowcaename[2:6]) == "cure" {
			fc.rawSecure = append(fc.rawSecure[:0], value...)
			fc.secure = true
			return
		}
	case "doma":
		if string(lowcaename[2:6]) == "main" {
			// 	If the first character of the attribute-value string is %x2E ("."):
			// 	Let cookie-domain be the attribute-value without the leading %x2E
			// 	(".") character.
			//  Otherwise:
			// 	Let cookie-domain be the entire attribute-value.
			if len(value) > 0 && value[0] == '.' {
				fc.domain = append(fc.domain[:0], value[1:]...)
			} else {
				fc.domain = append(fc.domain[:0], value...)
			}
			toLowercsaeASCII(fc.domain)
			return
		}
	}
	fc.set(name, lowcaename, value)
}

func (fc *FastCookie) set7(name, lowcaename []byte, value []byte) {
	_ = name[:7]
	_ = lowcaename[:7]
	switch string(lowcaename[:4]) {
	case "expi":
		if string(lowcaename[3:7]) == "ires" {
			fc.rawExpires = append(fc.rawExpires[:0], value...)
			exptime, err := time.Parse(time.RFC1123, b2s(value))
			if err != nil {
				exptime, err = time.Parse("Mon, 02-Jan-2006 15:04:05 MST", b2s(value))
				if err != nil {
					fc.expires = time.Time{}
					return
				}
			}
			fc.expires = exptime.UTC()
			return
		}
	case "max-":
		if string(lowcaename[3:7]) == "-age" {
			fc.rawMaxAge = append(fc.rawMaxAge[:0], value...)
			secs, err := strconv.Atoi(b2s(value))
			if err != nil || secs != 0 && value[0] == '0' {
				return
			}
			if secs <= 0 {
				secs = -1
			}
			fc.maxAge = secs
			return
		}
	}

	fc.set(name, lowcaename, value)
}

func (fc *FastCookie) set8(name, lowcaename []byte, value []byte) {
	_ = name[:8]
	_ = lowcaename[:8]
	switch string(lowcaename[:8]) {
	case "samesite":
		fc.tmpv = append(fc.tmpv[:0], value...)
		toLowercsaeASCII(fc.tmpv)
		fc.samesite = append(fc.samesite[:0], value...)
		return
	case "httponly":
		fc.httpOnly = true
		fc.rawHTTPOnly = append(fc.rawHTTPOnly[:0], value...)
		return
	}
	fc.set(name, lowcaename, value)
}
