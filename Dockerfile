FROM tier/shibbidp_configbuilder_container

RUN mkdir -p /webauthn/opt
Add nief /tmp
ADD opt /webauthn/opt
ADD webauthnAndConfigBuilder.sh /tmp


CMD /tmp/webauthnAndConfigBuilder.sh
