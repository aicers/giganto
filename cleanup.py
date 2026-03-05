with open('src/graphql/sysmon.rs') as f:
    lines = f.readlines()

# Keep lines 1-2208 (index 0-2207), skip 2209-3470 (index 2208-3469), keep 3471+ (index 3470+)
result = lines[:2208] + lines[3470:]

with open('src/graphql/sysmon.rs', 'w') as f:
    f.writelines(result)

print(f'Removed {len(lines) - len(result)} lines')
print(f'File now has {len(result)} lines')
