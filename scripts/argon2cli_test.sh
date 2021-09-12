echo -n "password" | argon2 somesalt $@ | grep -E "(Encoded|seconds)"
for ((i=0;i<2;i++)); do
    echo -n "password" | argon2 somesalt $@ | grep seconds
done