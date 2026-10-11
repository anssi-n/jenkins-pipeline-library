#!/bin/bash
set -e

HARBOR_URL="https://harbor.anyman.homelab"
AUTH="${HARBOR_USERNAME}:${HARBOR_PASSWORD}"
PROJECT="${1}"
REPO="${2}"
IMAGE_TAG="${3}"
CA_CERT="${4}"

echo "Analyzing accessories for ${REPO}:${IMAGE_TAG}..."

# 1. Fetch the artifact metadata to list all associated accessory artifacts
ARTIFACT_DATA=$(curl -s --cacert ${CA_CERT} -u "$AUTH" \
  "${HARBOR_URL}/api/v2.0/projects/${PROJECT}/repositories/${REPO}/artifacts/${IMAGE_TAG}?with_accessory=true")

# Extract all accessory digests
ACCESSORY_DIGESTS=$(echo "$ARTIFACT_DATA" | jq -r '.accessories[].digest')

if [ -z "$ACCESSORY_DIGESTS" ] || [ "$ACCESSORY_DIGESTS" == "null" ]; then
    echo "No accessories found for this image."
    exit 0
fi

# 2. Iterate through each accessory to pinpoint and destroy vulnerability scans
for ACC_DIGEST in $ACCESSORY_DIGESTS; do

    # Fetch the accessory's manifest to obtain its underlying blob layers
    MANIFEST=$(curl -s --cacert ${CA_CERT} -u "$AUTH" \
      -H "Accept: application/vnd.oci.image.manifest.v1+json" \
      -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
      "${HARBOR_URL}/v2/${PROJECT}/${REPO}/manifests/${ACC_DIGEST}")

    # Extract the digest of the actual data layer
    LAYER_DIGEST=$(echo "$MANIFEST" | jq -r '.layers[0].digest')

    if [ -z "$LAYER_DIGEST" ] || [ "$LAYER_DIGEST" == "null" ]; then
        continue
    fi

    # Download the payload layer blob using standard OCI registry routes
    BLOB_DATA=$(curl -sL --cacert ${CA_CERT} -u "$AUTH" \
      "${HARBOR_URL}/v2/${PROJECT}/${REPO}/blobs/${LAYER_DIGEST}")

    # Safely extract the inner predicate type if the file format matches an in-toto attestation
    PREDICATE_TYPE=$(echo "$BLOB_DATA" | jq -r 'try (.dsseEnvelope.payload | @base64d | fromjson | .predicateType) catch "none"')
    echo "ACC_DIGEST=${ACC_DIGEST}, PREDICATE_TYPE=${PREDICATE_TYPE}"
    # 3. Identify and drop the object if it is a vulnerability attestation
    if [ "$PREDICATE_TYPE" == "https://cosign.sigstore.dev/attestation/vuln/v1" ]; then
        echo "Found Vulnerability Scan Attestation ($ACC_DIGEST). Proceeding with deletion..."

        # Send the API DELETE instruction to Harbor
        DELETE_STATUS=$(curl -s --cacert ${CA_CERT} -o /dev/null -w "%{http_code}" -u "$AUTH" -X DELETE \
          "${HARBOR_URL}/api/v2.0/projects/${PROJECT}/repositories/${REPO}/artifacts/${ACC_DIGEST}")

        if [ "$DELETE_STATUS" -eq 200 ]; then
            echo "Successfully deleted vulnerability scan attestation."
        else
            echo "Failed to delete artifact. (HTTP Status: $DELETE_STATUS)"
        fi
    elif [[ "$PREDICATE_TYPE" == *"spdx"* ]] || [[ "$PREDICATE_TYPE" == *"cyclonedx"* ]]; then
        echo "Skipping $ACC_DIGEST (Identified as safely preserved SBOM)."
    else
        echo "Skipping $ACC_DIGEST (Identified as standard image signature)."
    fi
done