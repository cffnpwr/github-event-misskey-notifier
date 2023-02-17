FROM rust AS build

WORKDIR /app

RUN cargo init --bin

COPY Cargo.toml Cargo.lock ./

RUN --mount=type=cache,target=/usr/local/cargo/registry cargo build --release

COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry cargo build --release


FROM gcr.io/distroless/cc

COPY --from=build /app/target/release/github-event-misskey-notifier /ghemn

CMD [ "/ghemn" ]