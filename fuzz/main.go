// +build gofuzz

package cookie

import (
	"fmt"
	"reflect"

	"github.com/detailyang/fastcookie-go/fastcookie"
)

func FuzzCookie(data []byte) int {
	var (
		f1 fastcookie.FastCookie
		f2 fastcookie.FastCookie
	)

	f1.Parse([][]byte{data})
	d1 := f1.Encode(nil)
	f2.Parse([][]byte{d1})
	d2 := f2.Encode(nil)

	if !reflect.DeepEqual(d1, d2) {
		fmt.Printf("cookie1: %#v\n", string(d1))
		fmt.Printf("cookie2: %#v\n", string(d2))
		panic("fail")
	}
	return 1
}