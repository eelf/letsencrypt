## go let's encypt ##
A simple program in go enabling easy certificate renewal

### get ###
> go get github.com/eelf/letsencrypt

### provide config ###
see [schema](./config.schema.json) for config syntax
example:
```json
{
	"accounts": {
		"main": "letsencrypt_account.key"
	},
	"domains": {
		"example.com": {
			"account": "main",
			"remote": "domain_or_ssh_config_hostname",
			"token_dir": "/path/to/example.com/www/.well-known/acme-challenge",
			"private": "/path/to/example.com.key",
			"cert": "/path/to/example.com.cert"
		}
	}
}
```

### (optional) validate your config ###
> go get github.com/eelf/jsonschemacheck
> jsonschemacheck ~/go/pkg/mod/github.com/eelf/letsencrypt*/config.schema.json path/to/config.json

### update domain certificate ###
> letsencrypt path/to/config.json example.com

for remote domain User Port Hostname are taken from ~/.ssh/config if any
ssh-agent should contain key for that host
