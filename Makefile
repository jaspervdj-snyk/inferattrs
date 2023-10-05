blog.html: blog.md snippet.lua
	pandoc -s --lua-filter=snippet.lua -o $@ $<
