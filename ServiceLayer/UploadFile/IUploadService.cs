using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DataLayer.DTOs;
namespace ServiceLayer.UploadFile
{
    public interface IUploadService
    {
        Task<UploadResultDTO> UploadFileAsync(IFormFile file);

    }
}
