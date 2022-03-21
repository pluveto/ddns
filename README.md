# ddns

DDNS Cli util

## Support

+ Dnspod

## Usage

```shell
mkdir -p ~/app/ddns && cd $_
git clone http://github.com/pluveto/ddns .
cp start.example.sh start.sh
```

```shell
vi start.sh
# (edit and config)
chmod +x start.sh
./start.sh
```

## Auto update on boot

```shell
crontab -e
```