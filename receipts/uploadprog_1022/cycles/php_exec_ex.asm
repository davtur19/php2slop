
/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm:     file format elf64-x86-64


Disassembly of section .text:

0000000000a3bdfd <php_exec_ex>:
  a3bdfd:	41 57                	push   %r15
  a3bdff:	41 56                	push   %r14
  a3be01:	41 55                	push   %r13
  a3be03:	41 54                	push   %r12
  a3be05:	55                   	push   %rbp
  a3be06:	53                   	push   %rbx
  a3be07:	48 83 ec 18          	sub    $0x18,%rsp
  a3be0b:	49 89 f6             	mov    %rsi,%r14
  a3be0e:	83 fa 01             	cmp    $0x1,%edx
  a3be11:	be 02 00 00 00       	mov    $0x2,%esi
  a3be16:	83 d6 00             	adc    $0x0,%esi
  a3be19:	44 8b 7f 2c          	mov    0x2c(%rdi),%r15d
  a3be1d:	41 8d 47 ff          	lea    -0x1(%r15),%eax
  a3be21:	39 f0                	cmp    %esi,%eax
  a3be23:	73 53                	jae    a3be78 <php_exec_ex+0x7b>
  a3be25:	48 89 fd             	mov    %rdi,%rbp
  a3be28:	41 89 d4             	mov    %edx,%r12d
  a3be2b:	48 8d 5f 50          	lea    0x50(%rdi),%rbx
  a3be2f:	80 7f 58 06          	cmpb   $0x6,0x58(%rdi)
  a3be33:	75 73                	jne    a3bea8 <php_exec_ex+0xab>
  a3be35:	48 8b 47 50          	mov    0x50(%rdi),%rax
  a3be39:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
  a3be3e:	4c 8b 6c 24 08       	mov    0x8(%rsp),%r13
  a3be43:	4d 85 ed             	test   %r13,%r13
  a3be46:	74 13                	je     a3be5b <php_exec_ex+0x5e>
  a3be48:	49 8d 7d 18          	lea    0x18(%r13),%rdi
  a3be4c:	e8 4f 5b bc ff       	call   6019a0 <strlen@plt>
  a3be51:	49 39 45 10          	cmp    %rax,0x10(%r13)
  a3be55:	0f 85 18 01 00 00    	jne    a3bf73 <php_exec_ex+0x176>
  a3be5b:	45 85 e4             	test   %r12d,%r12d
  a3be5e:	75 6f                	jne    a3becf <php_exec_ex+0xd2>
  a3be60:	41 83 ff 01          	cmp    $0x1,%r15d
  a3be64:	0f 86 b9 01 00 00    	jbe    a3c023 <php_exec_ex+0x226>
  a3be6a:	48 8d 5d 60          	lea    0x60(%rbp),%rbx
  a3be6e:	48 89 dd             	mov    %rbx,%rbp
  a3be71:	b8 02 00 00 00       	mov    $0x2,%eax
  a3be76:	eb 61                	jmp    a3bed9 <php_exec_ex+0xdc>
  a3be78:	bf 01 00 00 00       	mov    $0x1,%edi
  a3be7d:	e8 18 18 12 00       	call   b5d69a <zend_wrong_parameters_count_error>
  a3be82:	bb 00 00 00 00       	mov    $0x0,%ebx
  a3be87:	be 00 00 00 00       	mov    $0x0,%esi
  a3be8c:	b9 00 00 00 00       	mov    $0x0,%ecx
  a3be91:	bf 01 00 00 00       	mov    $0x1,%edi
  a3be96:	49 89 d8             	mov    %rbx,%r8
  a3be99:	ba 00 00 00 00       	mov    $0x0,%edx
  a3be9e:	e8 73 1d 12 00       	call   b5dc16 <zend_wrong_parameter_error>
  a3bea3:	e9 bc 00 00 00       	jmp    a3bf64 <php_exec_ex+0x167>
  a3bea8:	48 8d 74 24 08       	lea    0x8(%rsp),%rsi
  a3bead:	ba 01 00 00 00       	mov    $0x1,%edx
  a3beb2:	48 89 df             	mov    %rbx,%rdi
  a3beb5:	e8 47 25 12 00       	call   b5e401 <zend_parse_arg_str_slow>
  a3beba:	84 c0                	test   %al,%al
  a3bebc:	75 80                	jne    a3be3e <php_exec_ex+0x41>
  a3bebe:	be 01 00 00 00       	mov    $0x1,%esi
  a3bec3:	b9 10 00 00 00       	mov    $0x10,%ecx
  a3bec8:	bf 09 00 00 00       	mov    $0x9,%edi
  a3becd:	eb c7                	jmp    a3be96 <php_exec_ex+0x99>
  a3becf:	bd 00 00 00 00       	mov    $0x0,%ebp
  a3bed4:	b8 01 00 00 00       	mov    $0x1,%eax
  a3bed9:	83 c0 01             	add    $0x1,%eax
  a3bedc:	48 83 c3 10          	add    $0x10,%rbx
  a3bee0:	41 39 c7             	cmp    %eax,%r15d
  a3bee3:	b8 00 00 00 00       	mov    $0x0,%eax
  a3bee8:	48 0f 42 d8          	cmovb  %rax,%rbx
  a3beec:	49 83 7d 10 00       	cmpq   $0x0,0x10(%r13)
  a3bef1:	0f 84 90 00 00 00    	je     a3bf87 <php_exec_ex+0x18a>
  a3bef7:	48 85 ed             	test   %rbp,%rbp
  a3befa:	0f 84 33 01 00 00    	je     a3c033 <php_exec_ex+0x236>
  a3bf00:	48 8b 45 00          	mov    0x0(%rbp),%rax
  a3bf04:	80 78 10 07          	cmpb   $0x7,0x10(%rax)
  a3bf08:	0f 85 b7 00 00 00    	jne    a3bfc5 <php_exec_ex+0x1c8>
  a3bf0e:	80 7d 08 0a          	cmpb   $0xa,0x8(%rbp)
  a3bf12:	74 7f                	je     a3bf93 <php_exec_ex+0x196>
  a3bf14:	4c 8b 65 00          	mov    0x0(%rbp),%r12
  a3bf18:	41 83 3c 24 01       	cmpl   $0x1,(%r12)
  a3bf1d:	77 7d                	ja     a3bf9c <php_exec_ex+0x19f>
  a3bf1f:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
  a3bf24:	48 8d 70 18          	lea    0x18(%rax),%rsi
  a3bf28:	4c 89 f1             	mov    %r14,%rcx
  a3bf2b:	48 89 ea             	mov    %rbp,%rdx
  a3bf2e:	bf 02 00 00 00       	mov    $0x2,%edi
  a3bf33:	e8 9f fc ff ff       	call   a3bbd7 <php_exec>
  a3bf38:	89 c5                	mov    %eax,%ebp
  a3bf3a:	48 85 db             	test   %rbx,%rbx
  a3bf3d:	74 25                	je     a3bf64 <php_exec_ex+0x167>
  a3bf3f:	48 8b 1b             	mov    (%rbx),%rbx
  a3bf42:	48 83 7b 18 00       	cmpq   $0x0,0x18(%rbx)
  a3bf47:	0f 85 c6 00 00 00    	jne    a3c013 <php_exec_ex+0x216>
  a3bf4d:	48 8d 7b 08          	lea    0x8(%rbx),%rdi
  a3bf51:	e8 52 7d 21 00       	call   c53ca8 <zval_ptr_safe_dtor>
  a3bf56:	48 63 ed             	movslq %ebp,%rbp
  a3bf59:	48 89 6b 08          	mov    %rbp,0x8(%rbx)
  a3bf5d:	c7 43 10 04 00 00 00 	movl   $0x4,0x10(%rbx)
  a3bf64:	48 83 c4 18          	add    $0x18,%rsp
  a3bf68:	5b                   	pop    %rbx
  a3bf69:	5d                   	pop    %rbp
  a3bf6a:	41 5c                	pop    %r12
  a3bf6c:	41 5d                	pop    %r13
  a3bf6e:	41 5e                	pop    %r14
  a3bf70:	41 5f                	pop    %r15
  a3bf72:	c3                   	ret
  a3bf73:	be 01 00 00 00       	mov    $0x1,%esi
  a3bf78:	b9 10 00 00 00       	mov    $0x10,%ecx
  a3bf7d:	bf 09 00 00 00       	mov    $0x9,%edi
  a3bf82:	e9 0f ff ff ff       	jmp    a3be96 <php_exec_ex+0x99>
  a3bf87:	bf 01 00 00 00       	mov    $0x1,%edi
  a3bf8c:	e8 e8 1c 12 00       	call   b5dc79 <zend_argument_must_not_be_empty_error>
  a3bf91:	eb d1                	jmp    a3bf64 <php_exec_ex+0x167>
  a3bf93:	48 8d 68 08          	lea    0x8(%rax),%rbp
  a3bf97:	e9 78 ff ff ff       	jmp    a3bf14 <php_exec_ex+0x117>
  a3bf9c:	4c 89 e7             	mov    %r12,%rdi
  a3bf9f:	e8 4e d6 1c 00       	call   c095f2 <zend_array_dup>
  a3bfa4:	48 89 45 00          	mov    %rax,0x0(%rbp)
  a3bfa8:	c7 45 08 07 03 00 00 	movl   $0x307,0x8(%rbp)
  a3bfaf:	41 f6 44 24 04 40    	testb  $0x40,0x4(%r12)
  a3bfb5:	0f 85 64 ff ff ff    	jne    a3bf1f <php_exec_ex+0x122>
  a3bfbb:	41 83 2c 24 01       	subl   $0x1,(%r12)
  a3bfc0:	e9 5a ff ff ff       	jmp    a3bf1f <php_exec_ex+0x122>
  a3bfc5:	e8 e9 76 1c 00       	call   c036b3 <_zend_new_array_0>
  a3bfca:	49 89 c4             	mov    %rax,%r12
  a3bfcd:	80 7d 08 0a          	cmpb   $0xa,0x8(%rbp)
  a3bfd1:	75 0f                	jne    a3bfe2 <php_exec_ex+0x1e5>
  a3bfd3:	4c 8b 6d 00          	mov    0x0(%rbp),%r13
  a3bfd7:	49 8d 6d 08          	lea    0x8(%r13),%rbp
  a3bfdb:	49 83 7d 18 00       	cmpq   $0x0,0x18(%r13)
  a3bfe0:	75 18                	jne    a3bffa <php_exec_ex+0x1fd>
  a3bfe2:	48 89 ef             	mov    %rbp,%rdi
  a3bfe5:	e8 be 7c 21 00       	call   c53ca8 <zval_ptr_safe_dtor>
  a3bfea:	4c 89 65 00          	mov    %r12,0x0(%rbp)
  a3bfee:	c7 45 08 07 03 00 00 	movl   $0x307,0x8(%rbp)
  a3bff5:	e9 25 ff ff ff       	jmp    a3bf1f <php_exec_ex+0x122>
  a3bffa:	48 89 c6             	mov    %rax,%rsi
  a3bffd:	4c 89 ef             	mov    %r13,%rdi
  a3c000:	e8 e9 ac 12 00       	call   b66cee <zend_try_assign_typed_ref_arr>
  a3c005:	83 f8 ff             	cmp    $0xffffffff,%eax
  a3c008:	0f 85 11 ff ff ff    	jne    a3bf1f <php_exec_ex+0x122>
  a3c00e:	e9 51 ff ff ff       	jmp    a3bf64 <php_exec_ex+0x167>
  a3c013:	48 63 f5             	movslq %ebp,%rsi
  a3c016:	48 89 df             	mov    %rbx,%rdi
  a3c019:	e8 59 ab 12 00       	call   b66b77 <zend_try_assign_typed_ref_long>
  a3c01e:	e9 41 ff ff ff       	jmp    a3bf64 <php_exec_ex+0x167>
  a3c023:	49 83 7d 10 00       	cmpq   $0x0,0x10(%r13)
  a3c028:	0f 84 59 ff ff ff    	je     a3bf87 <php_exec_ex+0x18a>
  a3c02e:	bb 00 00 00 00       	mov    $0x0,%ebx
  a3c033:	49 8d 75 18          	lea    0x18(%r13),%rsi
  a3c037:	4c 89 f1             	mov    %r14,%rcx
  a3c03a:	ba 00 00 00 00       	mov    $0x0,%edx
  a3c03f:	44 89 e7             	mov    %r12d,%edi
  a3c042:	e8 90 fb ff ff       	call   a3bbd7 <php_exec>
  a3c047:	89 c5                	mov    %eax,%ebp
  a3c049:	e9 ec fe ff ff       	jmp    a3bf3a <php_exec_ex+0x13d>

0000000000a3c04e <zif_exec>:
  a3c04e:	48 83 ec 08          	sub    $0x8,%rsp
  a3c052:	ba 00 00 00 00       	mov    $0x0,%edx
  a3c057:	e8 a1 fd ff ff       	call   a3bdfd <php_exec_ex>
  a3c05c:	48 83 c4 08          	add    $0x8,%rsp
  a3c060:	c3                   	ret

0000000000a3c061 <zif_system>:
  a3c061:	48 83 ec 08          	sub    $0x8,%rsp
  a3c065:	ba 01 00 00 00       	mov    $0x1,%edx
  a3c06a:	e8 8e fd ff ff       	call   a3bdfd <php_exec_ex>
  a3c06f:	48 83 c4 08          	add    $0x8,%rsp
  a3c073:	c3                   	ret
