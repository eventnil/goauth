package adaptors

import (
	"github.com/c0dev0yager/goauth/pkg/repository"
)

type RepositoryAdaptor struct {
	tr *repository.TokenRepository
}

func NewRepositoryAdaptor(
	tr *repository.TokenRepository,
) *RepositoryAdaptor {
	return &RepositoryAdaptor{tr: tr}
}

func (a *RepositoryAdaptor) Token() *repository.TokenRepository {
	return a.tr
}
