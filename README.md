<p align="center">
  <b>
    <span style="font-size:larger;">fastcookie-go</span>
  </b>
  <br />
   <a href="https://travis-ci.org/detailyang/fastcookie-go"><img src="https://travis-ci.org/detailyang/fastcookie-go.svg?branch=master" /></a>
   <a href="https://ci.appveyor.com/project/detailyang/fastcookie-go"><img src="https://ci.appveyor.com/api/projects/status/drc2xk4kcoiydr0x?svg=true" /></a>
   <br />
   <b>fastcookie-go is a yet another cookie parser but zero allocted which is more faster then net/http</b>
</p>

````bash
go test -v -benchmem -run="^$" github.com/detailyang/fastcookie-go/fastcookie -bench Benchmark
goos: darwin
goarch: amd64
pkg: github.com/detailyang/fastcookie-go/fastcookie
BenchmarkfastcookieParseCase1-8   	 5639812	       190 ns/op	       0 B/op	       0 allocs/op
BenchmarkNetURLParseCase1-8    	 1459245	       824 ns/op	     352 B/op	       7 allocs/op
BenchmarkfastcookieParseCase2-8   	 3414703	       364 ns/op	       0 B/op	       0 allocs/op
BenchmarkNetURLParseCase2-8    	  784420	      1461 ns/op	     528 B/op	       8 allocs/op
BenchmarkQuery-8               	 6587886	       170 ns/op	       0 B/op	       0 allocs/op
PASS
ok  	github.com/detailyang/fastcookie-go/fastcookie	7.405s
````
