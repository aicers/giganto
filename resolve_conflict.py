import re

with open('src/graphql/sysmon.rs') as f:
    content = f.read()

# Match the entire conflict block
pattern = r'<<<<<<< HEAD\n.*?>>>>>>> [^\n]*\n'
replacement = 'pub(crate) mod tests;\n'
result = re.sub(pattern, replacement, content, flags=re.DOTALL)

with open('src/graphql/sysmon.rs', 'w') as f:
    f.write(result)

print('Conflict resolved')
