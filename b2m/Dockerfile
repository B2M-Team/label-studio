# B2Metric build of Label Studio Community: the upstream image with the files listed in
# b2m/CHANGES.md copied over it. The base is pinned by digest and the layer below it is the
# unmodified upstream 1.23.2 release (Apache-2.0).
#
# Build from the repository root, for the linux/amd64 cluster:
#   docker buildx build --platform linux/amd64 -f b2m/Dockerfile -t <registry>/label-studio:<sha> --push .
#
# Before bumping the base, check that the overwritten files are still identical to the tag
# (b2m/verify-base.sh) or rebase the patch onto the new tag.
FROM heartexlabs/label-studio:1.23.2@sha256:afcc516a22775a39d0d66f4c2ddc95d01be3e3d3862b21fcf4f9de34b4ad4e12

# No chown: the image runs as uid 1001 and these files only need to be readable.
COPY label_studio/core/settings/base.py /label-studio/label_studio/core/settings/base.py
COPY label_studio/users/remote_user.py /label-studio/label_studio/users/remote_user.py

LABEL org.opencontainers.image.source="https://github.com/B2M-Team/label-studio" \
      org.opencontainers.image.base.name="docker.io/heartexlabs/label-studio:1.23.2" \
      org.opencontainers.image.licenses="Apache-2.0"
