runc-hook: main.go
	go build -o runc-hook main.go

test1:
	sudo ./runc-hook -verbose

test2:
	sudo ./runc-hook -hook-prestart=true -cmd 'cat > /tmp/hooks.log'

clean:
	rm -f runc-hook
