package adaptors

import (
	"github.com/c0dev0yager/goauth"
)

type RepositoryAdaptor struct {
	tr *goauth.TokenRepository
}

func NewRepositoryAdaptor(
	tr *goauth.TokenRepository,
) *RepositoryAdaptor {
	return &RepositoryAdaptor{tr: tr}
}

func (a *RepositoryAdaptor) Token() *goauth.TokenRepository {
	return a.tr
}
