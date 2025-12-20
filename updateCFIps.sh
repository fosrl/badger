rm CFIPs.txt
curl https://www.cloudflare.com/ips-v4 >>CFIPs.txt
echo "" >>CFIPs.txt
curl https://www.cloudflare.com/ips-v6 >>CFIPs.txt
echo "" >>CFIPs.txt

OUTPUT_GO_CONFIG="./ips/ips.go"
OUTPUT_GO_CONFIG_OLD="./ips-temp.go"

mv $OUTPUT_GO_CONFIG $OUTPUT_GO_CONFIG_OLD

echo "// Package ips contains a list of current cloud flare IP ranges" >>$OUTPUT_GO_CONFIG
echo "package ips" >>$OUTPUT_GO_CONFIG
echo "" >>$OUTPUT_GO_CONFIG
echo "// CFIPs is the CloudFlare Server IP list (this is checked on build)." >>$OUTPUT_GO_CONFIG
echo "func CFIPs() []string {" >>$OUTPUT_GO_CONFIG
echo "	return []string{" >>$OUTPUT_GO_CONFIG

cat CFIPs.txt | while read line || [[ -n $line ]]; do
  printf '%s\n' "CF IP: $line"
  echo "		\"${line}\"," >>$OUTPUT_GO_CONFIG
done

echo "	}" >>$OUTPUT_GO_CONFIG
echo "}" >>$OUTPUT_GO_CONFIG

rm CFIPs.txt

if [ "${1}" == "pc" ]; then
  echo "Run on pre-commit hook."
  if cmp --silent -- "$OUTPUT_GO_CONFIG" "$OUTPUT_GO_CONFIG_OLD"; then
    echo "No changes, nothing to worry about"
  else
    echo "Cloud flare have changed their IPs, adding changes to commit."
    touch ./.commit
  fi

  rm $OUTPUT_GO_CONFIG_OLD
  exit
fi

if [ "${1}" != "ci" ]; then
  echo "Not run on CI, exit ok"
  rm $OUTPUT_GO_CONFIG_OLD
  exit
fi

if cmp --silent -- "$OUTPUT_GO_CONFIG" "$OUTPUT_GO_CONFIG_OLD"; then
  echo "No changes to Cloud Flare IP list"
  rm $OUTPUT_GO_CONFIG_OLD
else
  echo "Cloud flare have changed their IPs, re-run updateCFIps.sh and commit the changes!"
  rm $OUTPUT_GO_CONFIG_OLD
  exit 6
fi

