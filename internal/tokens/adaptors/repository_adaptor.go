package adaptors

import (
	"github.com/c0dev0yager/goauth/internal"
)

type RepositoryAdaptor struct {
	tr *internal.TokenRepository
}

func NewRepositoryAdaptor(
	tr *internal.TokenRepository,
) *RepositoryAdaptor {
	return &RepositoryAdaptor{tr: tr}
}

func (a *RepositoryAdaptor) Token() *internal.TokenRepository {
	return a.tr
}
