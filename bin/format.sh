PKG_NAME=github.com/agungcandra/snap

find . -name '*.go' -type f | while read -r f; do
  awk '/^import \($/,/^\)$/{if($0=="")next}{print}' "${f}" > /tmp/file
  mv /tmp/file "${f}"
done

goimports -w -local ${PKG_NAME} $(go list -f {{.Dir}} ./...)
gofmt -s -w .
