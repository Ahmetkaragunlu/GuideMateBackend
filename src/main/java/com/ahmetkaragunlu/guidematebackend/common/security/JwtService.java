package com.ahmetkaragunlu.guidematebackend.common.security;

import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String TOKEN_VERSION_CLAIM = "tokenVersion";

    private final SecretKey signingKey;
    private final long jwtExpiration;
    private final Clock clock;

    public JwtService(
            @Value("${jwt.secret}") String secretKey,
            @Value("${jwt.expiration}") long jwtExpiration,
            Clock clock
    ) {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
        this.jwtExpiration = jwtExpiration;
        this.clock = clock;
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String generateToken(User user) {
        Instant issuedAt = clock.instant();
        return Jwts.builder()
                .claims(Map.of(TOKEN_VERSION_CLAIM, user.getTokenVersion()))
                .subject(user.getUsername())
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(issuedAt.plusMillis(jwtExpiration)))
                .signWith(signingKey)
                .compact();
    }

    public boolean isTokenValid(String token, User user) {
        try {
            Claims claims = extractAllClaims(token);
            Integer tokenVersion = claims.get(TOKEN_VERSION_CLAIM, Integer.class);
            return user.isEnabled()
                    && user.getUsername().equals(claims.getSubject())
                    && tokenVersion != null
                    && tokenVersion == user.getTokenVersion()
                    && claims.getExpiration().after(Date.from(clock.instant()));
        } catch (JwtException | IllegalArgumentException exception) {
            return false;
        }
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        return claimsResolver.apply(extractAllClaims(token));
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .clock(() -> Date.from(clock.instant()))
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
