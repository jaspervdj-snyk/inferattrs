.PHONY: build
build:
	mkdir dist
	pandoc -s --table-of-contents \
		--lua-filter=snippet.lua \
		-o dist/index.html blog.md
	cp screenshot.jpg dist

.PHONY: run
run:
	go run main.go
