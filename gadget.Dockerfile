# Prepare and build gadget artifacts in a container

# BCC built from the gadget branch in the kinvolk/bcc fork.
# See BCC section in docs/CONTRIBUTING.md for further details.
ARG BCC="quay.io/kinvolk/bcc:8654cd151c35ad20b3082e7d516a98a4e80d8899-focal-release"
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
	add-apt-repository -y ppa:tuxinvader/kernel-build-tools && \
	apt-add-repository -y ppa:longsleep/golang-backports && \
	apt-get update && \
	apt-get install -y libbpf-dev golang-1.17 && \
	ln -s /usr/lib/go-1.17/bin/go /bin/go

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

RUN apt-get update && apt-get install -qy llvm
# This COPY is limited by .dockerignore
COPY ./ /gadget
RUN cd /gadget && go mod vendor && rm -fr vendor/github.com/cilium/ebpf && cd vendor/github.com/cilium && git clone https://github.com/joamaki/ebpf.git && cd ebpf && git checkout pr/joamaki/bitfields
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

FROM docker.io/kinvolk/traceloop:20211109004128958575 as traceloop

# Main gadget image

FROM bcc

RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update && \
	apt-get install -y --no-install-recommends \
		ca-certificates curl jq wget xz-utils binutils rpm2cpio cpio && \
		rmdir /usr/src && ln -sf /host/usr/src /usr/src && \
		rm /etc/localtime && ln -sf /host/etc/localtime /etc/localtime

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
