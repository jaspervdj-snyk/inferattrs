default: inferattrs.html inferattrs.docx

inferattrs.%: blog.md snippet.lua main.go template.yml screenshot.jpg
	pandoc -s --table-of-contents --embed-resources \
		--lua-filter=snippet.lua -o $@ $<

.PHONY: run
run:
	go run main.go

.PHONY: deploy
deploy:
	rsync inferattrs.html freddy:jaspervdj.be/tmp/
