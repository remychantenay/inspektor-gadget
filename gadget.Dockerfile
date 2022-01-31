# Prepare and build gadget artifacts in a container

# BCC built from the gadget branch in the kinvolk/bcc fork.
# See BCC section in docs/CONTRIBUTING.md for further details.
ARG BCC="quay.io/kinvolk/bcc:302235e016b9a5255037c9075d28478557c0fc16-focal-release"
ARG OS_TAG=20.04

FROM ${BCC} as bcc
FROM ubuntu:${OS_TAG} as builder

ARG ENABLE_BTFGEN=false
ENV ENABLE_BTFGEN=${ENABLE_BTFGEN}

RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update && \
	apt-get install -y gcc make ca-certificates git clang \
		software-properties-common libseccomp-dev && \
	apt-add-repository -y ppa:longsleep/golang-backports && \
	apt-get update && \
	apt-get install -y golang-1.17 && \
	ln -s /usr/lib/go-1.17/bin/go /bin/go

# Install libbpf-dev from source to be cross-platform.
RUN git clone https://github.com/libbpf/libbpf.git && \
	cd libbpf/src && \
	make install

# Download BTFHub files
COPY ./tools /btf-tools
RUN set -ex; mkdir -p /tmp/btfs && \
	if [ "$ENABLE_BTFGEN" = true ]; then \
		cd /btf-tools && \
		./getbtfhub.sh; \
	fi

# Cache go modules so they won't be downloaded at each build
COPY go.mod go.sum /gadget/
RUN cd /gadget && go mod download

# This COPY is limited by .dockerignore
COPY ./ /gadget
RUN cd /gadget/gadget-container && make gadget-container-deps

# Execute BTFGen
COPY --from=bcc /objs /objs
RUN set -ex; \
	if [ "$ENABLE_BTFGEN" = true ]; then \
		cd /btf-tools && \
		LIBBPFTOOLS=/objs BTFHUB=/tmp/btfhub INSPEKTOR_GADGET=/gadget ./btfgen.sh; \
	fi

# Builder: traceloop

# traceloop built from:
# https://github.com/kinvolk/traceloop/commit/95857527df8d343a054d3754dc3b77c7c8c274c7
# See:
# - https://github.com/kinvolk/traceloop/actions
# - https://hub.docker.com/r/kinvolk/traceloop/tags

FROM docker.io/kinvolk/traceloop:2059b729c0ac8aa79016dacb06fbdaa1867c1446 as traceloop

# Main gadget image

FROM bcc

RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update && \
	apt-get install -y --no-install-recommends \
		ca-certificates curl jq wget xz-utils binutils && \
		rmdir /usr/src && ln -sf /host/usr/src /usr/src

COPY gadget-container/entrypoint.sh gadget-container/cleanup.sh /

COPY --from=builder /gadget/gadget-container/bin/gadgettracermanager /bin/
COPY --from=builder /gadget/gadget-container/bin/networkpolicyadvisor /bin/

COPY gadget-container/gadgets/bcck8s /opt/bcck8s/

COPY --from=traceloop /bin/traceloop /bin/

## Hooks Begins

# OCI
COPY gadget-container/hooks/oci/prestart.sh gadget-container/hooks/oci/poststop.sh /opt/hooks/oci/
COPY --from=builder /gadget/gadget-container/bin/ocihookgadget /opt/hooks/oci/

# cri-o
COPY gadget-container/hooks/crio/gadget-prestart.json gadget-container/hooks/crio/gadget-poststop.json /opt/hooks/crio/

# nri
COPY --from=builder /gadget/gadget-container/bin/nrigadget /opt/hooks/nri/
COPY gadget-container/hooks/nri/conf.json /opt/hooks/nri/

## Hooks Ends

# BTF files
COPY --from=builder /tmp/btfs /btfs/

# Mitigate https://github.com/kubernetes/kubernetes/issues/106962.
RUN rm /var/run
