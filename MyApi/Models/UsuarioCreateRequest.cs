namespace MyApi.Models
{
    public record UsuarioCreateRequest(
        string Username,
        string Password,
        string Nome,
        string Email,
        string Perfil,
        string? IPAutorizado
    );
}
