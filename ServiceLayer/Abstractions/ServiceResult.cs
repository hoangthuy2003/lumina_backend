using Microsoft.AspNetCore.Http;

namespace ServiceLayer.Abstractions;

public class ServiceResult<T>
{
    private ServiceResult(bool success, int statusCode, T? data, string? error)
    {
        Success = success;
        StatusCode = statusCode;
        Data = data;
        Error = error;
    }

    public bool Success { get; }

    public int StatusCode { get; }

    public T? Data { get; }

    public string? Error { get; }

    public static ServiceResult<T> Ok(T data, int statusCode = StatusCodes.Status200OK)
        => new(true, statusCode, data, null);

    public static ServiceResult<T> Fail(string error, int statusCode)
        => new(false, statusCode, default, error);
}
