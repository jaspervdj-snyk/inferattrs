blog.html: blog.md snippet.lua main.go template.yml
	pandoc -s --table-of-contents --lua-filter=snippet.lua -o $@ $<

.PHONY: run
run:
	go run main.go
