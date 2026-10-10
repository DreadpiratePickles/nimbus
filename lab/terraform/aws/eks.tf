# S07 (public EKS endpoint) and S08 (pod -> SA -> cluster-admin). Off unless enable_eks = true.
# Kubernetes objects (namespace ci, SA deployer, ClusterRoleBinding ci-deployer-admin, the
# LoadBalancer-exposed build-runner pod) live in k8s/ci-deployer.yaml and are applied with
# kubectl after the cluster exists; this keeps the kubernetes provider out of the plan.
data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_iam_role" "eks" {
  count = var.enable_eks ? 1 : 0
  name  = "nimbus-lab-eks-cluster-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "eks.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "eks" {
  count      = var.enable_eks ? 1 : 0
  role       = aws_iam_role.eks[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "lab" {
  count    = var.enable_eks ? 1 : 0
  name     = "nimbus-lab-eks"
  role_arn = aws_iam_role.eks[0].arn
  vpc_config {
    subnet_ids              = data.aws_subnets.default.ids
    endpoint_public_access  = true
    endpoint_private_access = false
    public_access_cidrs     = ["0.0.0.0/0"]
  }
  tags       = { nimbus_lab_id = "arn:aws:eks:us-east-1:111111111111:cluster/nimbus-lab-eks" }
  depends_on = [aws_iam_role_policy_attachment.eks]
}
