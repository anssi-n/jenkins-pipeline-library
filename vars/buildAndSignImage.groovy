def call(Map config = [:]) {
    
    def registry       = config.registry ?: "harbor.anyman.homelab"
    def imageName      = config.imageName
    def dockerfile     = config.dockerfile 
    def imageTag       = config.imageTag
    def isRelease      = config.isRelease ?: "false"
    def workspace      = config.workspace ?: env.WORKSPACE
    
    def safeImageId    = imageName.replace('/', '-')
    def digestFile     = "/home/jenkins/agent/${safeImageId}-kaniko.digest"

    container('kaniko') {
        script {
            def destinations = "--destination ${registry}/${imageName}:${imageTag}"
            if (isRelease == "true") {
                destinations += " --destination ${registry}/${imageName}:latest"
            }

            withEnv([
                "KANIKO_DESTINATIONS=${destinations}",
                "KANIKO_DOCKERFILE=${dockerfile}",
                "KANIKO_WORKSPACE=${workspace}",
                "KANIKO_DIGEST_FILE=${digestFile}",
                "KANIKO_CACHE_REPO=${imageName}-cache"
            ]) {
                sh '''
                    echo "Building and pushing image: $KANIKO_DESTINATIONS"
                    /kaniko/executor \
                        --context ${KANIKO_WORKSPACE} \
                        --dockerfile ${KANIKO_WORKSPACE}/${KANIKO_DOCKERFILE} \
                        ${KANIKO_DESTINATIONS} \
                        --cache=true \
                        --cache-repo=${KANIKO_CACHE_REPO} \
                        --digest-file=${KANIKO_DIGEST_FILE} \
                        --cleanup
                '''
            }
        }
    }

    withVault(vaultSecrets: [
        [
            path: 'cosign',
            engineVersion: 2,
            secretValues: [
                [vaultKey: 'password', envVar: 'COSIGN_PASSWORD'],
                [vaultKey: 'private_key', envVar: 'COSIGN_KEY_FILE']
            ]
        ]
    ]) {
        container('cosign') {
            withEnv([
                "DOCKER_CONFIG=/docker-config",
                "REGISTRY=${registry}",
                "IMAGE_NAME=${imageName}",
                "DIGEST_FILE=${digestFile}"
            ]) {
                sh '''
                    IMAGE_DIGEST=$(cat ${DIGEST_FILE})
                    
                    set +x 
                    echo "${COSIGN_KEY_FILE}" > /tmp/cosign.key
                    set -x

                    cosign version
                    echo "Signing image ${REGISTRY}/${IMAGE_NAME}@${IMAGE_DIGEST}"
                    cosign sign --key /tmp/cosign.key \
                        --new-bundle-format=false \
                        --use-signing-config=false \
                        "${REGISTRY}/${IMAGE_NAME}@${IMAGE_DIGEST}" --yes 
                    
                    rm -f /tmp/cosign.key
                '''
            }
        }
    }
}
