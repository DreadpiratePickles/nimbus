# allowed_cidrs is already declared in a sibling file; the patcher must not redeclare it.
variable "allowed_cidrs" {
  type = list(string)
}
