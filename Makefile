default: inferattrs.html inferattrs.docx

SOURCES=blog.md snippet.lua main.go template.yml screenshot.jpg

inferattrs.html: $(SOURCES)
	pandoc -s --table-of-contents --embed-resources \
		--lua-filter=snippet.lua -o $@ $<

inferattrs.docx: $(SOURCES)
	pandoc -s --embed-resources --lua-filter=snippet.lua -o $@ $<

.PHONY: run
run:
	go run main.go

.PHONY: deploy
deploy:
	rsync inferattrs.html freddy:jaspervdj.be/tmp/
