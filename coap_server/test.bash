coap-client -m get coap://192.168.0.143:5683/.well-known/core
echo -n "n n *" | coap-client -m put coap://192.168.0.143:5683/rpn -f-
coap-client -m get coap://192.168.0.143:5683/rpn?wyr=1&n=3
for i in {1...10}
do
	echo -n "n n *" | coap-client -m put coap://192.168.0.143:5683/rpn -f-
done
coap-client -m put coap://192.168.0.143:5683/rpn?all
coap-client -m get coap://192.168.0.143:5683/metrics/GET_inputs
coap-client -m get coap://192.168.0.143:5683/metrics/PUT_inputs
coap-client -m get coap://192.168.0.143:5683/metrics/Waiting_for_ACK
