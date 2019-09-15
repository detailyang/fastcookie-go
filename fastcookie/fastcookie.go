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

// FastCookie represents the cookie struct which defines in https://tools.ietf.org/html/rfc6265
type FastCookie struct {
	pairs       []CookiePair
	tmpk        []byte
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

func (fc FastCookie) String() string { return string(fc.Encode(nil)) }

// Encode encodes the cookie to dst
func (fc *FastCookie) Encode(dst []byte) []byte {
	return EncodeCookie(dst, fc)
}

// Parse pases the cookies to FastCookie
//
// HTTP2 RFC indicates request headres can allow more cookie header
func (fc *FastCookie) Parse(cookies [][]byte) {
	ParseCookie(fc, cookies)
}

// GetExpires gets the expire
func (fc *FastCookie) GetExpires() time.Time {
	return fc.expires
}

// GetRawExpires gets the raw expire
func (fc *FastCookie) GetRawExpires() []byte {
	return fc.rawExpires
}

// GetMaxAge gets the cookie max-age
func (fc *FastCookie) GetMaxAge() int {
	return fc.maxAge
}

// GetRawMaxAge gets the raw max-age
func (fc *FastCookie) GetRawMaxAge() []byte {
	return fc.rawMaxAge
}

// GetDomain gets the cookie domain
func (fc *FastCookie) GetDomain() []byte {
	return fc.domain
}

// GetPath gets the cookie path
func (fc *FastCookie) GetPath() []byte {
	return fc.path
}

// GetHTTPOnly gets the cookie httponly
func (fc *FastCookie) GetHTTPOnly() bool {
	return fc.httpOnly
}

// GetRawHTTPOnly gets the raw cookie httponly
func (fc *FastCookie) GetRawHTTPOnly() []byte {
	return fc.rawHTTPOnly
}

// GetSecure gets the cookie secure
func (fc *FastCookie) GetSecure() bool {
	return fc.secure
}

// GetRawSecure gets the raw cookie secure
func (fc *FastCookie) GetRawSecure() []byte {
	return fc.rawSecure
}

// GetSameSite gets the cookie samesite
func (fc *FastCookie) GetSameSite() []byte {
	return fc.samesite
}

// Reset resets the FastCookie
func (fc *FastCookie) Reset() {
	for i := range fc.pairs {
		fc.pairs[i].reset()
	}
	fc.pairs = fc.pairs[:0]
	fc.tmpk = fc.tmpk[:0]
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

func (fc *FastCookie) alloc() *CookiePair {
	n := len(fc.pairs)
	c := cap(fc.pairs)
	if n == c {
		fc.pairs = append(fc.pairs, make([]CookiePair, 4)...)
	}
	fc.pairs = fc.pairs[:n+1]
	return &fc.pairs[n]
}

func (fc *FastCookie) removeLastPair() {
	if n := len(fc.pairs); n >= 1 {
		fc.pairs = fc.pairs[:n-1]
	}
}

// GetAll returns all query who name is equal to name
func (fc *FastCookie) GetAll(name []byte, fn func(value []byte) bool) {
	for i := range fc.pairs {
		pair := fc.pairs[i]
		if bytes.Equal(pair.name, name) {
			if !fn(pair.value) {
				return
			}
		}
	}
}

// Get gets the value of name which do not include attribuets
func (fc *FastCookie) Get(name []byte) ([]byte, bool) {
	for i := range fc.pairs {
		if bytes.Equal(fc.pairs[i].name, name) {
			return fc.pairs[i].value, true
		}
	}
	return nil, false
}

// Del dels the name
func (fc *FastCookie) Del(name []byte) {
	fc.del(name, false)
}

// DelAll dels all the value who name is equal to name
func (fc *FastCookie) DelAll(name []byte) {
	fc.del(name, true)
}

func (fc *FastCookie) del(name []byte, all bool) {
	for i := 0; i < len(fc.pairs); i++ {
		pair := fc.pairs[i]
		if bytes.Equal(pair.name, name) {
			fc.pairs = append(fc.pairs[:i], fc.pairs[i+1:]...)
			if !all {
				return
			}
			i--
		}
	}
}

// Set sets the name and value
func (fc *FastCookie) Set(name, value []byte) {
	fc.tmpk = append(fc.tmpk[:0], name...)
	toLowercsaeASCII(fc.tmpk)
	switch len(fc.tmpk) {
	case 4:
		fc.set4(name[:4], fc.tmpk[:4], value)
	case 6:
		fc.set6(name[:6], fc.tmpk[:6], value)
	case 7:
		fc.set7(name[:7], fc.tmpk[:7], value)
	case 8:
		fc.set8(name[:8], fc.tmpk[:8], value)
	default:
		fc.Add(name, fc.tmpk, value)
	}
}

func (fc *FastCookie) set(name, lowcaename, value []byte) {
	for i := range fc.pairs {
		if bytes.Equal(fc.pairs[i].name, name) {
			fc.pairs[i].value = append(fc.pairs[i].value[:0], value...)
			return
		}
	}

	fc.Add(name, lowcaename, value)
}

// Add adds the name and value to cookie
func (fc *FastCookie) Add(name, lowcaename, value []byte) {
	pair := fc.alloc()
	pair.set(name, value)
}

func (fc *FastCookie) set4(name, lowcaename []byte, value []byte) {
	_ = name[:4]
	_ = lowcaename[:4]
	switch string(lowcaename[:4]) {
	case "path":
		// If the attribute-name case-insensitively matches the string "Path",
		// the user agent MUST process the cookie-av as follows.
		//
		// If the attribute-value is empty or if the first character of the
		// attribute-value is not %x2F ("/"):
		//
		//    Let cookie-path be the default-path.
		//
		// Otherwise:
		//
		//    Let cookie-path be the attribute-value.
		fc.path = append(fc.path[:0], value...)
		return
	}

	fc.Add(name, lowcaename, value)
}

func (fc *FastCookie) set6(name, lowcaename []byte, value []byte) {
	_ = name[:6]
	_ = lowcaename[:6]
	switch string(lowcaename[:4]) {
	case "secu":
		if string(lowcaename[2:6]) == "cure" {
			// If the attribute-name case-insensitively matches the string "Secure",
			// the user agent MUST append an attribute to the cookie-attribute-list
			// with an attribute-name of Secure and an empty attribute-value.
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

	fc.Add(name, lowcaename, value)
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

	fc.Add(name, lowcaename, value)
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

	fc.Add(name, lowcaename, value)
}

// EncodeCookie encodes cookie to dst
func EncodeCookie(dst []byte, c *FastCookie) []byte {
	if c.maxAge > 0 {
		dst = append(dst, ';', ' ')
		dst = append(dst, "max-age="...)
		dst = strconv.AppendInt(dst, int64(c.maxAge), 10)

	} else if !c.expires.IsZero() {
		dst = append(dst, ';', ' ')
		dst = append(dst, "expires="...)
		dst = c.expires.In(time.UTC).AppendFormat(dst, time.RFC1123)
		copy(dst[len(dst)-3:], "GMT")
	}

	if len(c.domain) > 0 {
		dst = append(dst, "; domain="...)
		dst = append(dst, c.domain...)
	}

	if len(c.path) > 0 {
		dst = append(dst, "; path="...)
		dst = append(dst, c.path...)
	}

	if c.httpOnly {
		dst = append(dst, ';', ' ')
		dst = append(dst, "HttpOnly"...)
	}

	if c.secure {
		dst = append(dst, ';', ' ')
		dst = append(dst, "secure"...)
	}

	if len(c.samesite) > 0 {
		dst = append(dst, ';', ' ')
		dst = append(dst, "SameSite"...)
		dst = append(dst, '=')
		dst = append(dst, c.samesite...)
	}

	return dst
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
	ck := c.tmpk[:0]
	cv := c.tmpv[:0]

	for i := range cookies {
		cookie := cookies[i]
		var part []byte
		for len(cookie) > 0 {

			ci := bytes.IndexByte(cookie, ';')
			if ci >= 0 {
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
