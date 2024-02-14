.PHONY: build
build:
	mkdir -p dist
	pandoc -s --table-of-contents \
	    --include-in-header=style.html \
		--lua-filter=snippet.lua \
		-o dist/index.html blog.md
	cp screenshot.jpg dist

.PHONY: run
run:
	go run main.go
