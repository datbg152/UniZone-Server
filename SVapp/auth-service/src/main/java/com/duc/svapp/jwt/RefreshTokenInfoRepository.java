package com.duc.svapp.jwt;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RefreshTokenInfoRepository extends CrudRepository<RefreshTokenInfo, String> {
}