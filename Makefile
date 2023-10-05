blog.html: blog.md snippet.lua main.go template.yml
	pandoc -s --lua-filter=snippet.lua -o $@ $<

.PHONY: run
run:
	go run main.go
