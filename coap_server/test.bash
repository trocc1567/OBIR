coap-client -m get coap://192.168.0.143:5683/.well-known/core
coap-client -m get coap://192.168.0.143:5683/time
coap-client -m get coap://192.168.0.143:5683/colour
echo -n "20 276 -30" | coap-client -m put coap://192.168.0.143:5683/colour -f-
coap-client -m get coap://192.168.0.143:5683/colour
echo -n "n n *" | coap-client -m put coap://192.168.0.143:5683/rpn -f-
coap-client -m get coap://192.168.0.143:5683/rpn?wyr=1&n=3
for i in {1...10}
do
	echo -n "n n *" | coap-client -m put coap://192.168.0.143:5683/rpn -f-
done
coap-client -m put coap://192.168.0.143:5683/rpn?all
coap-client -m get coap://192.168.0.143:5683/metrics/metric1
coap-client -m get coap://192.168.0.143:5683/metrics/metric2
coap-client -m get coap://192.168.0.143:5683/metrics/metric3
