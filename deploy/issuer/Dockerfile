FROM scratch

COPY openstack-tpm-issuer /openstack-tpm-issuer

USER 65532:65532
EXPOSE 8443

ENTRYPOINT ["/openstack-tpm-issuer"]
